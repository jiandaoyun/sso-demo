package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt"
)

const (
	tenantURL = "https://portal.finecloud.com/portal/tenant/620a31c23e7c5a00081e7acf"
	// acs：简道云中生成的认证返回地址
	acs = tenantURL + "/sso/custom/acs"
	// 未传入登出回程地址时，跳回租户登录页。
	logoutReturnURL = tenantURL + "/signin"
	// issuer：Issuer URL
	issuer = "com.angelmsger"
	// username：需要进行单点登录的成员ID
	username = "angelmsger"
	// secret：认证密钥
	secret = "fHVI4PztDMHShqZzkLbuS8hn"
)

func verifyRequest(request, expectedType string) (jwt.MapClaims, error) {
	parser := jwt.Parser{
		ValidMethods: []string{"HS256", "HS384", "HS512"},
		// 由下方校验时间声明，以支持与 Node.js 示例相同的时钟容差。
		SkipClaimsValidation: true,
	}
	token, err := parser.Parse(request, func(_ *jwt.Token) (any, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid || claims["iss"] != "com.jiandaoyun" || claims["type"] != expectedType {
		return nil, errors.New("unexpected issuer or request type")
	}
	// 简道云中未配置 Issuer URL 时，注释以下代码。
	if !hasAudience(claims["aud"]) {
		return nil, errors.New("unexpected audience")
	}

	const clockTolerance = float64(time.Hour / time.Second)
	now := float64(time.Now().Unix())
	if value, exists := claims["exp"]; exists || expectedType == "slo_req" {
		if expiry, ok := value.(float64); !ok || now >= expiry+clockTolerance {
			return nil, errors.New("invalid or expired exp claim")
		}
	}
	if value, exists := claims["nbf"]; exists {
		if notBefore, ok := value.(float64); !ok || notBefore > now+clockTolerance {
			return nil, errors.New("invalid or future nbf claim")
		}
	}
	return claims, nil
}

func hasAudience(audience any) bool {
	if audiences, ok := audience.([]any); ok {
		for _, value := range audiences {
			if value == issuer {
				return true
			}
		}
		return false
	}
	return audience == issuer
}

func signResponse(username, sessionID string) (string, error) {
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
	return token.SignedString([]byte(secret))
}

func newHandler() http.Handler {
	// 演示用的 IdP 会话记录，进程重启后清空。
	sessions := make(map[string]string)
	var sessionsMu sync.Mutex
	mux := http.NewServeMux()
	mux.HandleFunc("/sso", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		if _, err := verifyRequest(query.Get("request"), "sso_req"); err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var randomBytes [16]byte
		if _, err := rand.Read(randomBytes[:]); err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		sessionID := hex.EncodeToString(randomBytes[:])
		response, err := signResponse(username, sessionID)
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		sessionsMu.Lock()
		sessions[sessionID] = strings.TrimSpace(username)
		sessionsMu.Unlock()

		callbackQuery := url.Values{"response": {response}}
		if state := query.Get("state"); state != "" {
			callbackQuery.Set("state", state)
		}
		http.Redirect(w, r, acs+"?"+callbackQuery.Encode(), http.StatusSeeOther)
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		query, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || len(query["request"]) != 1 {
			http.Error(w, "无效的单点登出请求。", http.StatusBadRequest)
			return
		}
		claims, err := verifyRequest(query.Get("request"), "slo_req")
		if err != nil {
			http.Error(w, "无效的单点登出请求。", http.StatusBadRequest)
			return
		}

		index, _ := claims["index"].(string)
		nameID, _ := claims["nameId"].(string)
		sessionsMu.Lock()
		member, exists := sessions[index]
		matchesSession := !exists || nameID == member
		if matchesSession {
			// 已清理或进程重启过时，delete 不会影响其他会话。
			delete(sessions, index)
		}
		sessionsMu.Unlock()
		if !matchesSession {
			http.Error(w, "无效的单点登出请求。", http.StatusBadRequest)
			return
		}

		target := logoutReturnURL
		if redirects, supplied := query["redirect_uri"]; supplied {
			redirect, err := url.Parse(query.Get("redirect_uri"))
			if len(redirects) != 1 || err != nil || redirect.Hostname() == "" || redirect.User != nil ||
				(redirect.Scheme != "http" && redirect.Scheme != "https") {
				http.Error(w, "无效的登出返回地址。", http.StatusBadRequest)
				return
			}
			target = redirect.String()
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
	})
	return mux
}

func main() {
	log.Fatal(http.ListenAndServe(":8080", newHandler()))
}
