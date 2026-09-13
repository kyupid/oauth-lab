// 리소스서버(Resource Server) — :9001
//
// !!! 학습용 코드다. 실제 서비스에 쓰지 말 것 !!!
//
// 이 파일에서 확인할 것: "누구인가" 를 묻는 줄이 한 줄도 없다.
// 리소스서버는 요청자의 신원을 확인하지 않는다. 토큰이 유효한지, 그리고
// 그 토큰이 이 엔드포인트에 필요한 scope 를 담고 있는지만 본다.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const (
	asURL = "http://127.0.0.1:9000"
	// 리소스서버가 인가서버에 자기를 증명할 자격증명. introspection 을 부르려면 필요하다.
	rsID     = "resource-server"
	rsSecret = "rs-secret"
)

// 이 리소스서버의 정체. 두 벌을 띄워 서로 다른 리소스인 상황을 만들 수 있게 환경변수로 받는다.
//
//	RS_PORT=9004 RS_NAME=빌링 RS_SCOPE=billing:read go run ./cmd/resource
var (
	rsPort  = env("RS_PORT", "9001")
	rsName  = env("RS_NAME", "노트")
	rsScope = env("RS_SCOPE", "notes:read")
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// selfURL 은 이 리소스서버의 식별자다. 토큰의 aud 가 이 값이어야 한다.
func selfURL() string { return "http://127.0.0.1:" + rsPort }

func main() {
	// 엔드포인트마다 요구하는 scope 가 다르다. 이게 "인가" 의 실체다.
	http.Handle("/me", requireScope("profile", handleMe))
	http.Handle("/data", requireScope(rsScope, handleData))
	http.Handle("/notes", requireScope(rsScope, handleData)) // 1부 호환 별칭

	// RFC 9728 Protected Resource Metadata — 이 리소스서버가 자기를 소개하는 문서.
	http.HandleFunc("/.well-known/oauth-protected-resource", handlePRM)

	log.Printf("[RS:%s] listening on %s  (scope=%s)", rsName, selfURL(), rsScope)
	log.Fatal(http.ListenAndServe("127.0.0.1:"+rsPort, nil))
}

// ---------------------------------------------------------------------------
// 토큰 검증
// ---------------------------------------------------------------------------

// introspection 은 인가서버가 돌려주는 토큰 정보다 (RFC 7662).
type introspection struct {
	Active   bool   `json:"active"`
	Scope    string `json:"scope"`
	Sub      string `json:"sub"`
	ClientID string `json:"client_id"`
	Exp      int64  `json:"exp"`
}

// requireScope 는 Bearer 토큰을 꺼내 인가서버에 물어보고, scope 를 확인한 뒤 통과시킨다.
func requireScope(scope string, next func(http.ResponseWriter, *http.Request, introspection)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// OAuth 2.1: 토큰은 Authorization 헤더로만 받는다.
		// 쿼리스트링(?access_token=...)은 서버 로그·리퍼러·히스토리에 남아서 금지됐다.
		if r.URL.Query().Get("access_token") != "" {
			unauthorized(w, http.StatusBadRequest, "invalid_request",
				"토큰을 쿼리스트링으로 보내지 마세요. Authorization 헤더를 쓰세요.")
			return
		}

		token, ok := bearerToken(r)
		if !ok {
			// 토큰이 없을 때도 PRM 위치를 알려준다. 클라이언트는 이걸 보고 AS 를 찾아간다.
			unauthorized(w, http.StatusUnauthorized, "invalid_request", "인증 정보가 없습니다")
			return
		}

		// JWT 면 로컬 검증(서명만 확인, AS 왕복 없음), opaque 면 introspection(AS 에 왕복).
		var info introspection
		var err error
		if looksLikeJWT(token) {
			info, err = verifyJWT(token)
			if err != nil {
				unauthorized(w, http.StatusUnauthorized, "invalid_token", err.Error())
				return
			}
		} else {
			info, err = introspect(token)
			if err != nil {
				http.Error(w, "인가서버에 물어볼 수 없습니다: "+err.Error(), http.StatusBadGateway)
				return
			}
		}
		if !info.Active {
			// 401: 토큰 자체가 못 쓴다 (없음/만료/폐기).
			unauthorized(w, http.StatusUnauthorized, "invalid_token", "만료됐거나 알 수 없는 토큰")
			return
		}
		if !hasScope(info.Scope, scope) {
			// 403: 토큰은 멀쩡한데 권한이 모자란다. 다시 로그인해도 소용없고,
			// 더 넓은 scope 로 새로 받아와야 한다 — 그래서 401 이 아니라 403 이다.
			unauthorized(w, http.StatusForbidden, "insufficient_scope", "이 리소스에는 '"+scope+"' 가 필요합니다")
			return
		}

		log.Printf("[RS] 통과 %s  scope=%q sub=%q", r.URL.Path, info.Scope, info.Sub)
		next(w, r, info)
	})
}

// bearerToken 은 "Authorization: Bearer xxx" 에서 xxx 를 꺼낸다.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	// 스킴 이름은 대소문자를 가리지 않는다 (RFC 7235).
	if len(h) < 7 || !strings.EqualFold(h[:7], "bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(h[7:])
	return tok, tok != ""
}

// introspect 는 인가서버에 "이 토큰 유효해?" 라고 묻는다. 매 요청마다 왕복이 생긴다
// — 스텝 6에서 JWT 로 바꿔 이 왕복을 없앤다.
func introspect(token string) (introspection, error) {
	req, err := http.NewRequest(http.MethodPost, asURL+"/introspect",
		strings.NewReader(url.Values{"token": {token}}.Encode()))
	if err != nil {
		return introspection{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(rsID, rsSecret) // 리소스서버가 자기를 증명한다

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return introspection{}, err
	}
	defer resp.Body.Close()

	var info introspection
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return introspection{}, err
	}
	return info, nil
}

// hasScope 는 공백으로 구분된 scope 목록에 해당 scope 가 있는지 본다.
// 부분 문자열 비교가 아니라 정확히 한 항목과 일치해야 한다
// ("notes" 가 "notes:read" 를 통과시키면 안 된다).
func hasScope(granted, want string) bool {
	for _, s := range strings.Fields(granted) {
		if s == want {
			return true
		}
	}
	return false
}

// unauthorized 는 RFC 6750 형식의 에러를 돌려준다.
// 클라이언트가 "다시 로그인해야 하나, 더 넓은 권한을 받아야 하나" 를 구분할 수 있게 해준다.
func unauthorized(w http.ResponseWriter, status int, code, desc string) {
	// RFC 9728: 클라이언트가 "어느 AS 로 가야 하나" 를 알 수 있도록 PRM 위치를 함께 알려준다.
	w.Header().Set("WWW-Authenticate",
		`Bearer error="`+code+`", error_description="`+desc+`", `+
			`resource_metadata="`+selfURL()+`/.well-known/oauth-protected-resource"`)
	http.Error(w, code+": "+desc, status)
}

// ---------------------------------------------------------------------------
// 보호된 리소스
// ---------------------------------------------------------------------------

func handleMe(w http.ResponseWriter, r *http.Request, info introspection) {
	// 사용자가 누구인지는 요청이 알려준 게 아니라, 토큰에 담겨 있던 것이다.
	writeJSON(w, map[string]any{
		"sub":   info.Sub,
		"scope": info.Scope,
	})
}

func handleData(w http.ResponseWriter, r *http.Request, info introspection) {
	// 리소스서버마다 다른 데이터를 돌려준다. 어느 서버의 응답인지 구분하려고 rsName 을 함께 싣는다.
	data := map[string]map[string][]string{
		"노트": {
			"alice": {"장보기: 사과, 커피", "OAuth 2.1 문서 읽기"},
			"bob":   {"밥의 비밀 메모"},
		},
		"빌링": {
			"alice": {"2026-09 청구서 42,000원", "카드 끝자리 4242"},
			"bob":   {"밥의 청구서 9,900원"},
		},
	}
	writeJSON(w, map[string]any{
		"server": rsName,
		"owner":  info.Sub,
		"items":  data[rsName][info.Sub],
	})
}

// handlePRM — RFC 9728. "나는 누구이고, 어느 인가서버를 믿으며, 무슨 scope 를 요구하는가."
// 클라이언트는 401 의 WWW-Authenticate 에서 이 문서 위치를 얻어 읽고,
// 그 다음 어느 AS 로 가야 하는지 알아낸다. AS 를 미리 알 필요가 없어진다.
func handlePRM(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"resource":                 selfURL(),
		"authorization_servers":    []string{asURL},
		"scopes_supported":         []string{"profile", rsScope},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            rsName,
	})
}

func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(body)
}
