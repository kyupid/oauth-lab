package main

// 2.1 이 제거한 grant 들 — 왜 편리했고 왜 위험한지 직접 겪어보기 위한 것.
// 기본 비활성. ./lab enable implicit / ./lab enable ropc 로만 켜진다.

import (
	"log"
	"net/http"
	"net/url"

	"oauth-lab/internal/lab"
)

// grantImplicit — access token 을 front channel(URL fragment)로 직접 준다.
// code 단계가 없다. 그래서 토큰이 브라우저 히스토리·리퍼러에 그대로 남는다.
// 2.1 이 제거한 이유가 이거다.
func grantImplicit(w http.ResponseWriter, r *http.Request, clientID, redirectURI, scope, state string) {
	// 동의 없이 바로 토큰을 만든다 (실습 단순화). 실제 implicit 도 동의 후 fragment 로 줬다.
	token := accessTokenJWT("alice", scope, "http://127.0.0.1:9001")

	// 핵심: 쿼리(?)가 아니라 fragment(#) 로 붙인다. fragment 는 서버로 안 가지만
	// 브라우저 주소창·히스토리에는 남고, JS 로 읽을 수 있어 노출면이 크다.
	u := redirectURI + "#access_token=" + url.QueryEscape(token) +
		"&token_type=Bearer&expires_in=60&scope=" + url.QueryEscape(scope)
	if state != "" {
		u += "&state=" + url.QueryEscape(state)
	}
	log.Printf("[AS] ⚠️ implicit: access token 을 URL fragment 로 반환 (2.1 제거 대상)")
	http.Redirect(w, r, u, http.StatusFound)
}

// grantPassword — ROPC. 앱이 사용자의 아이디/비밀번호를 직접 받아 AS 로 넘긴다.
// OAuth 의 존재 이유(앱이 비번을 안 보게 하는 것)를 정면으로 위반한다. 2.1 제거.
func grantPassword(w http.ResponseWriter, r *http.Request) {
	if !lab.On("ropc") {
		jsonError(w, http.StatusBadRequest, "unsupported_grant_type",
			"password(ROPC)는 2.1에서 제거됨 (./lab enable ropc 로 실습)")
		return
	}
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	// 여기서 AS 가 비번을 검증한다 — 그런데 이 비번은 앱을 통해 들어왔다.
	// 즉 앱이 사용자 비번을 봤다는 뜻. 이게 문제의 핵심이다.
	log.Printf("[AS] ⚠️ ROPC: 앱이 넘긴 사용자 비번을 직접 받음 user=%s pass=%s (2.1 제거 대상)", username, password)

	token := accessTokenJWT(username, "profile notes:read", "http://127.0.0.1:9001")
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token, "token_type": "Bearer", "expires_in": 60,
		"scope": "profile notes:read",
	})
}

// handleDiscovery — 기계가 읽는 AS 설명서 (RFC 8414).
func handleDiscovery(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"introspection_endpoint":                issuer + "/introspect",
		"jwks_uri":                              issuer + "/.well-known/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
	})
}
