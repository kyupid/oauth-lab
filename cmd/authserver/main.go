// 인가서버(Authorization Server) — :9000
//
// !!! 학습용 코드다. 실제 서비스에 쓰지 말 것 !!!
// 비밀번호 검사도, 세션 고정 방어도, 레이트 리밋도, 영속성도 없다.
//
// 스텝 1 상태: 일부러 취약하게 만들어 둔 부분이 있다. 각각 [VULN] 로 표시했고,
// 스텝 3~5 에서 직접 깨본 뒤 하나씩 막는다.
//
//	[VULN-1] state 를 그냥 되돌려주기만 한다 (검증은 클라이언트 책임인데 스텝 1 클라이언트는 안 한다)
//	[VULN-2] redirect_uri 를 prefix 매칭으로 느슨하게 검증한다
//	[VULN-3] 인가코드에 만료도, 1회용 제한도 없다
//	[VULN-4] PKCE 가 없다
//
// lab_step 파라미터는 랩 전용이다. 붙어 있으면 302 로 즉시 넘어가는 대신
// "지금 브라우저가 어디로 떠밀리는 중인지"를 보여주는 화면에서 멈춘다.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"oauth-lab/internal/lab"
	"oauth-lab/internal/store"
)

const issuer = "http://127.0.0.1:9000"

var db = store.New()

func main() {
	initSigningKey()
	db.RegisterClient(store.Client{
		ID:          "demo-app",
		Secret:      "demo-secret",
		RedirectURI: "http://127.0.0.1:9002/callback",
	})
	// 리소스서버도 인가서버에 등록된 클라이언트다 — introspection 을 부르려면 자격증명이 필요하다.
	db.RegisterClient(store.Client{
		ID:     "resource-server",
		Secret: "rs-secret",
	})
	db.RegisterClient(store.Client{
		ID:          "public-app", // 스텝 5(PKCE)에서 쓸 공개 클라이언트
		Secret:      "",
		RedirectURI: "http://127.0.0.1:9002/callback",
	})

	http.HandleFunc("/authorize", handleAuthorize)
	http.HandleFunc("/approve", handleApprove)
	http.HandleFunc("/token", handleToken)
	http.HandleFunc("/introspect", handleIntrospect)
	http.HandleFunc("/.well-known/jwks.json", handleJWKS)
	http.HandleFunc("/.well-known/oauth-authorization-server", handleDiscovery)
	http.HandleFunc("/userinfo", handleUserInfo)
	http.HandleFunc("/connect/register", handleRegister)
	http.HandleFunc("/oauth2/revoke", handleRevoke)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "authorization server (%s)\n/authorize  /approve  /token\n", issuer)
	})

	log.Printf("[AS] listening on %s", issuer)
	log.Fatal(http.ListenAndServe("127.0.0.1:9000", logging("AS", http.DefaultServeMux)))
}

// ---------------------------------------------------------------------------
// front channel: 브라우저가 직접 방문한다. 여기 오가는 값은 전부 URL 에 남는다.
// ---------------------------------------------------------------------------

var consentTmpl = template.Must(template.New("consent").Parse(`<!doctype html>
<meta charset="utf-8"><title>로그인 · 인가서버</title>
<style>` + lab.CSS + `</style>
{{.Banner}}
<p class="step">{{if .Step}}③ / ⑥  {{end}}브라우저 ↔ 인가서버</p>
{{.BadgeHTML}}
<h1>인가서버 (:9000)</h1>
<p><b>{{.ClientID}}</b> 앱이 요청한 권한: <code>{{.Scope}}</code></p>
<form method="POST" action="/approve">
  <p><label>사용자 이름 <input name="username" value="alice" required></label></p>
  <input type="hidden" name="client_id" value="{{.ClientID}}">
  <input type="hidden" name="redirect_uri" value="{{.RedirectURI}}">
  <input type="hidden" name="scope" value="{{.Scope}}">
  <input type="hidden" name="state" value="{{.State}}">
  <input type="hidden" name="code_challenge" value="{{.CodeChallenge}}">
  <input type="hidden" name="code_challenge_method" value="{{.CodeChallengeMethod}}">
  <input type="hidden" name="nonce" value="{{.Nonce}}">
  <input type="hidden" name="resource" value="{{.Resource}}">
  {{if .Step}}<input type="hidden" name="lab_step" value="1">{{end}}
  <p><button class="btn" type="submit">허용</button></p>
</form>
`))

type consentData struct {
	ClientID, RedirectURI, Scope, State string
	CodeChallenge, CodeChallengeMethod  string
	Nonce                               string
	Resource                            string
	Step                                bool
}

func (consentData) BadgeHTML() template.HTML { return lab.Badge(lab.KindUserView) }
func (consentData) Banner() template.HTML    { return lab.ServerBanner("9000") }

func handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	responseType := q.Get("response_type")
	scope := q.Get("scope")
	state := q.Get("state")
	codeChallenge := q.Get("code_challenge")
	codeChallengeMethod := q.Get("code_challenge_method")
	nonce := q.Get("nonce")
	resource := q.Get("resource") // RFC 8707
	step := q.Get("lab_step") == "1"

	client, ok := db.Client(clientID)
	if !ok {
		// client_id 가 틀리면 리다이렉트하면 안 된다. 화면에 직접 에러를 띄운다.
		httpError(w, http.StatusBadRequest, "invalid_client", "등록되지 않은 client_id")
		return
	}
	// redirect_uri 검증. 방어 ON: 등록값과 문자열 완전 일치만 허용 (OAuth 2.1).
	//                    방어 OFF(./lab off redirect): prefix 매칭 — /callback.evil, /callback?next=... 통과
	var okRedirect bool
	if lab.Off("redirect") {
		okRedirect = strings.HasPrefix(redirectURI, client.RedirectURI)
	} else {
		okRedirect = redirectURI == client.RedirectURI
	}
	if !okRedirect {
		httpError(w, http.StatusBadRequest, "invalid_request",
			"redirect_uri 불일치 (등록값: "+client.RedirectURI+")")
		return
	}
	if responseType == "token" {
		// [2.1 이 제거함] Implicit grant. lab.On("implicit") 일 때만 동작한다.
		if !lab.On("implicit") {
			redirectError(w, r, redirectURI, state, "unsupported_response_type",
				"implicit(response_type=token)은 2.1에서 제거됨 (./lab enable implicit 로 실습)")
			return
		}
		grantImplicit(w, r, clientID, redirectURI, scope, state)
		return
	}
	if responseType != "code" {
		redirectError(w, r, redirectURI, state, "unsupported_response_type", "code 또는 token")
		return
	}
	if scope == "" {
		scope = "profile"
	}
	// RFC 8707: 모르는 리소스를 대상으로 지정하면 거부한다.
	// 이 검사가 없으면 공격자가 임의의 aud 로 토큰을 받아갈 수 있다.
	if resource != "" && !isKnownResource(resource) {
		redirectError(w, r, redirectURI, state, "invalid_target", "알 수 없는 resource: "+resource)
		return
	}

	// PKCE 방어 ON: challenge 없는 요청 거부. 2.1 은 S256 만 인정한다 (plain 금지).
	if !lab.Off("pkce") {
		if codeChallenge == "" {
			redirectError(w, r, redirectURI, state, "invalid_request", "code_challenge 가 필요합니다 (PKCE 필수)")
			return
		}
		if codeChallengeMethod != "S256" {
			redirectError(w, r, redirectURI, state, "invalid_request", "code_challenge_method 는 S256 이어야 합니다")
			return
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = consentTmpl.Execute(w, consentData{clientID, redirectURI, scope, state, codeChallenge, codeChallengeMethod, nonce, resource, step})
}

func handleApprove(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		httpError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	clientID := r.PostForm.Get("client_id")
	redirectURI := r.PostForm.Get("redirect_uri")
	scope := r.PostForm.Get("scope")
	state := r.PostForm.Get("state")
	username := r.PostForm.Get("username")
	codeChallenge := r.PostForm.Get("code_challenge")
	codeChallengeMethod := r.PostForm.Get("code_challenge_method")
	nonce := r.PostForm.Get("nonce")
	resource := r.PostForm.Get("resource")
	step := r.PostForm.Get("lab_step") == "1"

	if _, ok := db.Client(clientID); !ok {
		httpError(w, http.StatusBadRequest, "invalid_client", "등록되지 않은 client_id")
		return
	}

	code := store.RandString(24)
	db.SaveCode(&store.AuthCode{
		Code:                code,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Subject:             username,
		Scope:               scope,
		CreatedAt:           time.Now(),
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Nonce:               nonce,
		Resource:            resource,
	})
	log.Printf("[AS] 인가코드 발급 code=%s sub=%s scope=%s", code, username, scope)

	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state) // [VULN-1] 되돌려주기만 한다. 검증은 클라이언트 몫.
	}
	u.RawQuery = q.Encode()

	if !step {
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}
	lab.RenderHop(w, lab.Hop{
		Port:        "9000",
		Step:        "③.5 / ⑥  인가서버 → 브라우저",
		Kind:        lab.KindAutoRedirect,
		Title:       "인가서버가 code 를 들려 브라우저를 돌려보낸다",
		Explain:     `인가서버가 302 하나를 주고, 브라우저가 redirect_uri 를 따라갑니다. 나가는 건 토큰이 아니라 code 입니다.`,
		Params:      lab.QueryKV(u.String(), "code", "state"),
		RawRequest:  "HTTP/1.1 302 Found\nLocation: " + u.String(),
		ContinueURL: u.String(), ContinueLabel: "브라우저가 따라간다 →",
	})
}

// ---------------------------------------------------------------------------
// back channel: 클라이언트 "서버"가 호출한다. 브라우저는 이 요청을 보지 못한다.
// ---------------------------------------------------------------------------

func handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "invalid_request", "POST 만 허용")
		return
	}
	if err := r.ParseForm(); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		grantAuthorizationCode(w, r)
	case "refresh_token":
		grantRefreshToken(w, r)
	case "password":
		grantPassword(w, r)
	default:
		jsonError(w, http.StatusBadRequest, "unsupported_grant_type", "authorization_code 만 지원")
	}
}

func grantAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	codeStr := r.PostForm.Get("code")
	clientID := r.PostForm.Get("client_id")
	clientSecret := r.PostForm.Get("client_secret")

	client, ok := db.Client(clientID)
	if !ok {
		jsonError(w, http.StatusUnauthorized, "invalid_client", "등록되지 않은 client_id")
		return
	}
	// 기밀 클라이언트만 secret 을 검사한다. 공개 클라이언트는 secret 이 없다
	// — 그래서 스텝 5의 PKCE 가 필요해진다.
	if client.Secret != "" && client.Secret != clientSecret {
		jsonError(w, http.StatusUnauthorized, "invalid_client", "client_secret 불일치")
		return
	}

	ac, ok := db.Code(codeStr)
	if !ok {
		jsonError(w, http.StatusBadRequest, "invalid_grant", "알 수 없는 code")
		return
	}
	if ac.ClientID != clientID {
		jsonError(w, http.StatusBadRequest, "invalid_grant", "다른 클라이언트에게 발급된 code")
		return
	}
	// [VULN-4] code_verifier 확인이 없다. 스텝 5에서 추가한다.

	// code 1회용 + 만료 검증. 방어 ON: 재사용/만료 거부. OFF(./lab off onetime): 무한 재사용.
	if lab.Off("onetime") {
		if ac.Used {
			log.Printf("[AS] ⚠️  이미 쓴 code 를 또 통과시킴 (%s) — onetime 방어가 꺼져 있음", codeStr)
		}
	} else {
		if time.Since(ac.CreatedAt) > 60*time.Second {
			jsonError(w, http.StatusBadRequest, "invalid_grant", "만료된 code (60초 초과)")
			return
		}
		if ac.Used {
			// 재사용 = 탈취 신호. 이 code 로 이미 나간 토큰까지 전부 폐기한다.
			n := db.RevokeTokensFromCode(ac.Code)
			log.Printf("[AS] 🚨 code 재사용 감지 (%s) — 발급됐던 토큰 %d개 폐기", codeStr, n)
			jsonError(w, http.StatusBadRequest, "invalid_grant", "이미 사용된 code (재사용 감지 — 관련 토큰 전부 폐기됨)")
			return
		}
	}

	// PKCE 검증. code 발급 때 저장해둔 challenge 와, 지금 온 verifier 를 S256 해시한 값이 같아야 한다.
	// code 를 훔쳐도 verifier(앱만 아는 원본)가 없으면 여기서 막힌다.
	if !lab.Off("pkce") || ac.CodeChallenge != "" {
		verifier := r.PostForm.Get("code_verifier")
		if ac.CodeChallenge == "" {
			// PKCE 없이 발급된 code (방어 OFF 시절). 방어가 켜져 있으면 거부.
			if !lab.Off("pkce") {
				jsonError(w, http.StatusBadRequest, "invalid_grant", "이 code 에는 PKCE 가 없습니다")
				return
			}
		} else {
			if verifier == "" {
				jsonError(w, http.StatusBadRequest, "invalid_grant", "code_verifier 가 필요합니다")
				return
			}
			sum := sha256.Sum256([]byte(verifier))
			calc := base64.RawURLEncoding.EncodeToString(sum[:])
			if calc != ac.CodeChallenge {
				jsonError(w, http.StatusBadRequest, "invalid_grant", "code_verifier 불일치 (code 를 훔쳐도 verifier 없이는 못 씀)")
				return
			}
		}
	}

	// RFC 8707: 토큰의 대상(aud)을 정한다.
	// /token 의 resource 는 /authorize 때 지정한 것과 같아야 한다 — 중간에 대상을 바꿔치기할 수 없다.
	aud := r.PostForm.Get("resource")
	if ac.Resource != "" && aud != "" && aud != ac.Resource {
		jsonError(w, http.StatusBadRequest, "invalid_target",
			"authorize 때 지정한 resource 와 다릅니다 (authorize: "+ac.Resource+")")
		return
	}
	if aud == "" {
		aud = ac.Resource
	}
	if aud != "" && !isKnownResource(aud) {
		jsonError(w, http.StatusBadRequest, "invalid_target", "알 수 없는 resource: "+aud)
		return
	}
	if aud == "" {
		aud = "http://127.0.0.1:9001" // 지정 안 하면 기본 리소스 (1부 호환)
	}

	tokenValue := store.RandString(32) // opaque (jwt 방어를 끈 경우)
	if !lab.Off("jwt") {
		tokenValue = accessTokenJWT(ac.Subject, ac.Scope, aud)
	}
	tok := &store.Token{
		Value:     tokenValue,
		ClientID:  clientID,
		Subject:   ac.Subject,
		Scope:     ac.Scope,
		ExpiresAt: time.Now().Add(60 * time.Second),
		FromCode:  ac.Code,
	}
	db.SaveToken(tok)
	ac.Used = true

	// refresh token 도 함께 발급한다. 새 Family 를 연다.
	rt := issueRefresh("", clientID, ac.Subject, ac.Scope)
	log.Printf("[AS] 토큰 발급 sub=%s scope=%s", tok.Subject, tok.Scope)

	out := map[string]any{
		"access_token":  tok.Value,
		"refresh_token": rt.Value,
		"token_type":    "Bearer",
		"expires_in":    int(time.Until(tok.ExpiresAt).Seconds()),
		"scope":         tok.Scope,
	}
	// OIDC: scope 에 openid 가 있으면 id_token 도 발급한다.
	if hasOpenID(ac.Scope) {
		out["id_token"] = signIDToken(ac.Subject, clientID, ac.Nonce)
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// introspection (RFC 7662) — 리소스서버가 "이 토큰 유효해?" 라고 되묻는 창구.
// 이것도 back channel 이다. 브라우저는 이 엔드포인트를 부를 일이 없다.
// ---------------------------------------------------------------------------

func handleIntrospect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "invalid_request", "POST 만 허용")
		return
	}
	if err := r.ParseForm(); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// 이 엔드포인트는 반드시 보호해야 한다. 아무나 부를 수 있으면
	// "이 토큰 살아있어?" 를 무한히 물어볼 수 있는 신탁(oracle)이 된다.
	id, secret, ok := r.BasicAuth()
	caller, found := db.Client(id)
	if !ok || !found || caller.Secret == "" || caller.Secret != secret {
		w.Header().Set("WWW-Authenticate", `Basic realm="introspection"`)
		jsonError(w, http.StatusUnauthorized, "invalid_client", "리소스서버 자격증명이 필요합니다")
		return
	}

	tok, exists := db.Token(r.PostForm.Get("token"))
	// RFC 7662: 모르는 토큰이라고 404 를 주면 안 된다. active:false 로 답한다.
	// 그래야 "존재는 하는데 만료됨" 과 "아예 없음" 을 구분당하지 않는다.
	if !exists || time.Now().After(tok.ExpiresAt) {
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"active":    true,
		"scope":     tok.Scope,
		"sub":       tok.Subject,
		"client_id": tok.ClientID,
		"exp":       tok.ExpiresAt.Unix(),
		"iss":       issuer,
	})
}

func hasOpenID(scope string) bool {
	for _, s := range strings.Fields(scope) {
		if s == "openid" {
			return true
		}
	}
	return false
}
