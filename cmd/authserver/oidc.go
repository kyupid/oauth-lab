package main

// OpenID Connect — OAuth 위에 "인증(누구인가)" 을 표준으로 얹는 계층.
//
// 핵심 차이:
//   access token : aud = 리소스서버.  "무엇을 할 수 있나" (권한).  RS 가 쓴다.
//   id_token     : aud = 클라이언트.  "누구인가" (신원).           앱이 쓴다.
//
// id_token 은 앱이 직접 열어 sub 를 읽는다 — /me 를 호출할 필요가 없다.
// nonce 로 "이 id_token 이 방금 내가 시작한 로그인의 것" 임을 보장한다 (replay 방지).

import (
	"net/http"
	"strings"
	"time"
)

// signIDToken 은 OIDC id_token 을 만든다. aud 는 리소스서버가 아니라 "클라이언트" 다.
func signIDToken(sub, clientID, nonce string) string {
	now := time.Now()
	claims := map[string]any{
		"iss":       issuer,
		"sub":       sub,
		"aud":       clientID, // ← access token 과 결정적 차이: 수신자가 앱이다
		"exp":       now.Add(5 * time.Minute).Unix(),
		"iat":       now.Unix(),
		"auth_time": now.Unix(), // 언제 인증했나 (access token 엔 없는 정보)
	}
	if nonce != "" {
		claims["nonce"] = nonce // 앱이 보낸 값을 그대로 되돌려준다 → 앱이 대조
	}
	return signJWT(claims)
}

// handleUserInfo — OIDC UserInfo 엔드포인트. access token 으로 사용자 정보를 준다.
// (access token 은 "누구인가" 를 직접 안 담으므로, 알고 싶으면 여기 물어본다.)
func handleUserInfo(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		w.Header().Set("WWW-Authenticate", "Bearer")
		jsonError(w, http.StatusUnauthorized, "invalid_token", "Bearer 토큰 필요")
		return
	}
	tokenVal := strings.TrimSpace(auth[7:])
	tok, ok := db.Token(tokenVal)
	if !ok || time.Now().After(tok.ExpiresAt) {
		jsonError(w, http.StatusUnauthorized, "invalid_token", "만료됐거나 알 수 없는 토큰")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"sub":  tok.Subject,
		"name": strings.Title(tok.Subject),
	})
}
