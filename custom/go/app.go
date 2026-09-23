package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
)

const (
	// acs：简道云中生成的认证返回地址
	acs = "https://portal.finecloud.com/portal/tenant/620a31c23e7c5a00081e7acf/sso/custom/acs"
	// issuer：Issuer URL
	issuer = "com.angelmsger"
	// username：需要进行单点登录的成员ID
	username = "angelmsger"
	// secret：认证密钥
	secret = "fHVI4PztDMHShqZzkLbuS8hn"
)

func ValidBody(body jwt.MapClaims) bool {
	if body["iss"] != "com.jiandaoyun" || body["type"] != "sso_req" {
		return false
	}

	// 简道云中未配置 Issuer URL 时，注释以下代码
	if body["aud"] != issuer {
		return false
	}

	return true
}

func ValidToken(query string) bool {
	token, err := jwt.Parse(query, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected Signing Method: %v ", token.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return false
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	return ok && token.Valid && ValidBody(claims)
}

func GetTokenByUsername(username string) (string, error) {
	now := time.Now()
	token := jwt.NewWithClaims(
		// 与简道云中配置的 认证加密算法 保持一致
		jwt.SigningMethodHS256, jwt.MapClaims{
			"type":     "sso_res",
			"username": username,
			// 简道云中未配置 Issuer URL 时，注释以下一行
			"iss": issuer,
			"aud": "com.jiandaoyun",
			"nbf": now.Unix(),
			"iat": now.Unix(),
			"exp": now.Add(1 * time.Minute).Unix(),
		})
	return token.SignedString([]byte(secret))
}

func BuildResponseUri(token string, state string) string {
	target := acs + "?response=" + token
	if state != "" {
		target += "&state=" + state
	}
	return target
}

func main() {
	http.HandleFunc("/sso", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		reqToken := query.Get("request")
		if ValidToken(reqToken) {
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
	log.Fatal(http.ListenAndServe(":8080", nil))
}
