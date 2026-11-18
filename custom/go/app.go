package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
)

const (
	// acs：简道云中生成的认证返回地址
	acs = "https://portal.finecloud.com/portal/tenant/620a31c23e7c5a00081e7acf/sso/custom/acs"
	// 未传入登出回程地址时，跳回租户登录页。
	logoutReturnURL = "https://portal.finecloud.com/portal/tenant/620a31c23e7c5a00081e7acf/signin"
	// issuer：Issuer URL
	issuer = "com.angelmsger"
	// username：需要进行单点登录的成员ID
	username = "angelmsger"
	// secret：认证密钥
	secret = "fHVI4PztDMHShqZzkLbuS8hn"
)

// 演示用的 IdP 会话记录。
var sessions sync.Map

func ValidBody(body jwt.MapClaims, expectedType string) bool {
	if body["iss"] != "com.jiandaoyun" || body["type"] != expectedType {
		return false
	}

	// 简道云中未配置 Issuer URL 时，注释以下代码
	if body["aud"] != issuer {
		return false
	}

	return true
}

// 登录和登出共用 JWT 校验，通过 expectedType 区分请求类型。
// 校验成功时返回 JWT 内容供登出使用，失败时返回 nil。
func verifyRequest(request, expectedType string) jwt.MapClaims {
	token, err := jwt.Parse(request, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected Signing Method: %v ", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid || !ValidBody(claims, expectedType) {
		return nil
	}
	return claims
}

func GetTokenByUsername(username string) (string, error) {
	var randomBytes [16]byte
	if _, err := rand.Read(randomBytes[:]); err != nil {
		return "", err
	}
	sessionID := hex.EncodeToString(randomBytes[:])
	now := time.Now()
	token := jwt.NewWithClaims(
		// 与简道云中配置的 认证加密算法 保持一致
		jwt.SigningMethodHS256, jwt.MapClaims{
			"type":     "sso_res",
			"username": username,
			// 简道云将 jti 记录为会话索引，并在单点登出时传回。
			"jti": sessionID,
			// 简道云中未配置 Issuer URL 时，注释以下一行
			"iss": issuer,
			"aud": "com.jiandaoyun",
			"nbf": now.Unix(),
			"iat": now.Unix(),
			"exp": now.Add(1 * time.Minute).Unix(),
		})
	response, err := token.SignedString([]byte(secret))
	// 签名成功后记录 jti 对应的成员，供登出时核对。
	if err == nil {
		sessions.Store(sessionID, strings.TrimSpace(username))
	}
	return response, err
}

func BuildResponseUri(token string, state string) string {
	target := acs + "?response=" + token
	if state != "" {
		target += "&state=" + state
	}
	return target
}

func logout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// 校验登出请求。
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query["request"]) != 1 {
		http.Error(w, "无效的单点登出请求。", http.StatusBadRequest)
		return
	}
	claims := verifyRequest(query.Get("request"), "slo_req")
	if claims == nil {
		http.Error(w, "无效的单点登出请求。", http.StatusBadRequest)
		return
	}

	// 清除会话。
	index, _ := claims["index"].(string)
	if member, exists := sessions.Load(index); exists && member != claims["nameId"] {
		http.Error(w, "无效的单点登出请求。", http.StatusBadRequest)
		return
	}
	sessions.Delete(index)

	target := logoutReturnURL
	if redirects, supplied := query["redirect_uri"]; supplied {
		// 校验登出地址。
		redirect, err := url.Parse(query.Get("redirect_uri"))
		if len(redirects) != 1 || err != nil || redirect.Hostname() == "" || redirect.User != nil ||
			(redirect.Scheme != "http" && redirect.Scheme != "https") {
			http.Error(w, "无效的登出返回地址。", http.StatusBadRequest)
			return
		}
		target = redirect.String()
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func main() {
	http.HandleFunc("/sso", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		reqToken := query.Get("request")
		if verifyRequest(reqToken, "sso_req") != nil {
			if resToken, err := GetTokenByUsername(username); err == nil {
				target := BuildResponseUri(resToken, query.Get("state"))
				http.Redirect(w, r, target, http.StatusSeeOther)
			} else {
				w.WriteHeader(403)
			}
		} else {
			w.WriteHeader(403)
		}
	})
	http.HandleFunc("/logout", logout)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
