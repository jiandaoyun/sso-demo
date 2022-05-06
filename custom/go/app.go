package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
)

const (
	acs      = "https://www.jiandaoyun.com/sso/custom/5b4bf4398aa34804a574bfcb/acs"
	issuer   = "com.angelmsger"
	username = "angelmsger"
	secret   = "fHVI4PztDMHShqZzkLbuS8hn"
)

func ValidBody(body jwt.MapClaims) bool {
	return body["iss"] == "com.jiandaoyun" && body["aud"] == issuer && body["type"] == "sso_req"
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
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"type":     "sso_res",
		"username": username,
		"iss":      issuer,
		"aud":      "com.jiandaoyun",
		"nbf":      now.Unix(),
		"iat":      now.Unix(),
		"exp":      now.Add(1 * time.Minute).Unix(),
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
