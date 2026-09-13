package main

// refresh token 회전 + 재사용 감지 (스텝 7)
//
// 회전(rotation): refresh 를 쓸 때마다 새 refresh 를 발급하고 이전 것을 무효화한다.
// 재사용 감지: 이미 쓴(회전된) refresh 가 또 오면 = 누군가 훔쳐서 쓰고 있다는 신호.
//   → 그 Family 전체를 폐기한다. 진짜 사용자도 같이 끊기지만, 그게 안전하다.

import (
	"log"
	"net/http"
	"time"

	"oauth-lab/internal/lab"
	"oauth-lab/internal/store"
)

// issueRefresh 는 새 refresh token 을 만든다. family 가 비면 새 Family 를 연다.
func issueRefresh(family, clientID, sub, scope string) *store.RefreshToken {
	if family == "" {
		family = store.RandString(8)
	}
	rt := &store.RefreshToken{
		Value:     store.RandString(24),
		Family:    family,
		ClientID:  clientID,
		Subject:   sub,
		Scope:     scope,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	db.SaveRefresh(rt)
	return rt
}

func grantRefreshToken(w http.ResponseWriter, r *http.Request) {
	presented := r.PostForm.Get("refresh_token")
	clientID := r.PostForm.Get("client_id")

	rt, ok := db.Refresh(presented)
	if !ok {
		jsonError(w, http.StatusBadRequest, "invalid_grant", "알 수 없는 refresh token")
		return
	}
	if time.Now().After(rt.ExpiresAt) {
		jsonError(w, http.StatusBadRequest, "invalid_grant", "만료된 refresh token")
		return
	}

	// 재사용 감지: 이미 회전된(쓴) refresh 가 또 왔다.
	if rt.Used && !lab.Off("rotation") {
		n := db.RevokeFamily(rt.Family)
		log.Printf("[AS] 🚨 refresh 재사용 감지 (family=%s) — %d개 폐기. 이 세션은 다시 로그인해야 한다.", rt.Family, n)
		jsonError(w, http.StatusBadRequest, "invalid_grant",
			"refresh token 재사용 감지 — 이 Family 전체 폐기됨 (탈취 의심)")
		return
	}

	// 새 access token 발급
	var accessVal string
	if !lab.Off("jwt") {
		accessVal = accessTokenJWT(rt.Subject, rt.Scope, "http://127.0.0.1:9001")
	} else {
		accessVal = store.RandString(32)
	}
	db.SaveToken(&store.Token{
		Value: accessVal, ClientID: clientID, Subject: rt.Subject,
		Scope: rt.Scope, ExpiresAt: time.Now().Add(60 * time.Second),
	})

	resp := map[string]any{
		"access_token": accessVal,
		"token_type":   "Bearer",
		"expires_in":   60,
		"scope":        rt.Scope,
	}

	if lab.Off("rotation") {
		// 방어 OFF: 회전 안 함. 같은 refresh 를 계속 재사용 가능 (탈취돼도 감지 못 함).
		resp["refresh_token"] = rt.Value
	} else {
		// 방어 ON: 회전. 이전 것 무효화하고 같은 Family 로 새 refresh 발급.
		rt.Used = true
		newRT := issueRefresh(rt.Family, clientID, rt.Subject, rt.Scope)
		resp["refresh_token"] = newRT.Value
		log.Printf("[AS] refresh 회전 (family=%s) 이전 것 무효화", rt.Family)
	}
	writeJSON(w, http.StatusOK, resp)
}
