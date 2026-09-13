package main

// RFC 7009 Token Revocation — 클라이언트가 능동적으로 "이 토큰 버려주세요" 하는 엔드포인트.
//
// 1부에서 refresh 재사용이 감지되면 AS 가 알아서 폐기했다(스텝 7). 그건 서버의 방어다.
// revocation 은 반대로 클라이언트가 요청하는 것이다. 로그아웃할 때, 토큰이 더 필요 없을 때.
//
// 주의: JWT access token 은 리소스서버가 로컬 검증하므로(스텝 6), revoke 해도
// 만료(60초) 전까지는 리소스서버가 계속 통과시킨다. 그래서 revocation 의 실질 효과는
// 주로 refresh token 에 있다 — refresh 를 죽이면 새 access 를 못 받으니 곧 세션이 끝난다.

import (
	"log"
	"net/http"
)

func handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "invalid_request", "POST 만 허용")
		return
	}
	if err := r.ParseForm(); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	token := r.PostForm.Get("token")
	if token == "" {
		jsonError(w, http.StatusBadRequest, "invalid_request", "token 파라미터가 필요합니다")
		return
	}

	// refresh 인지 access(opaque) 인지 모르므로 둘 다 시도한다.
	// RFC 7009: 어느 쪽이든, 심지어 모르는 토큰이어도 200 을 돌려준다
	// — 공격자가 "이 토큰이 존재하나"를 revoke 응답으로 알아내지 못하게 한다.
	if db.DeleteRefresh(token) {
		log.Printf("[AS] revoke: refresh token 폐기 (+Family)")
	} else if db.DeleteToken(token) {
		log.Printf("[AS] revoke: access token 폐기")
	} else {
		log.Printf("[AS] revoke: 모르는 토큰 (그래도 200)")
	}
	w.WriteHeader(http.StatusOK)
}
