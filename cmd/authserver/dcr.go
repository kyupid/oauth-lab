package main

// RFC 7591 Dynamic Client Registration — 클라이언트가 런타임에 스스로 등록한다.
//
// 1부에서는 demo-app, public-app 을 코드에 하드코딩해 등록했다.
// Claude Code 같은 외부 클라이언트는 사전 등록이 불가능하다. 사용자가 자기 노트북에서
// 처음 실행하는 순간 client_id 가 없으니, 스스로 등록해 client_id 를 발급받는다.
//
// 누가 등록하는지를 통제하지 않으면 아무나 클라이언트를 만들 수 있다. 실제 서비스는
// 초기 액세스 토큰이나 심사를 두지만, 여기서는 그 자리(정책 지점)만 표시해 둔다.

import (
	"encoding/json"
	"log"
	"net/http"

	"oauth-lab/internal/lab"
	"oauth-lab/internal/store"
)

type dcrRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name"`
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "invalid_request", "POST 만 허용")
		return
	}
	// DCR 은 SaaS 프로파일에서만 연다. 온프렘은 설치 시 provisioning 하므로 필요 없다.
	if !lab.On("dcr") {
		jsonError(w, http.StatusForbidden, "access_denied",
			"DCR 이 꺼져 있습니다 (./lab enable dcr 로 실습)")
		return
	}

	var req dcrRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid_client_metadata", "JSON 파싱 실패")
		return
	}
	if len(req.RedirectURIs) == 0 {
		jsonError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris 가 필요합니다")
		return
	}
	// [정책 지점] 실제로는 여기서 redirect_uri 스킴·호스트를 검증한다.
	// 외부 클라이언트는 보통 loopback(127.0.0.1:랜덤포트)이나 커스텀 스킴만 허용한다.

	id := "dcr-" + store.RandString(8)
	// 공개 클라이언트로 등록한다(secret 없음). 그래서 PKCE 가 필수가 된다(스텝 5).
	client := store.Client{
		ID:          id,
		Secret:      "",
		RedirectURI: req.RedirectURIs[0], // 실습 단순화: 첫 번째만 저장
	}
	db.RegisterClient(client)
	log.Printf("[AS] DCR 등록: %s (name=%q redirect=%s)", id, req.ClientName, client.RedirectURI)

	// RFC 7591: 발급된 client_id 와, 등록 시 서버가 확정한 메타데이터를 돌려준다.
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  id,
		"client_name":                req.ClientName,
		"redirect_uris":              []string{client.RedirectURI},
		"token_endpoint_auth_method": "none", // 공개 클라이언트
		"grant_types":                []string{"authorization_code", "refresh_token"},
	})
}
