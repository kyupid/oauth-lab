// 클라이언트 앱(Client / Relying Party) — :9002
//
// !!! 학습용 코드다. 실제 서비스에 쓰지 말 것 !!!
//
// 스텝 1 상태:
//
//	[VULN-1] state 를 아예 보내지 않는다 → 스텝 3에서 CSRF 로 세션을 탈취당한다
//	[VULN-4] PKCE 를 쓰지 않는다 → 스텝 5에서 code 가 새면 그대로 끝난다
//
// 이 앱은 "스텝 모드"를 지원한다. 켜면 원래 눈 깜짝할 새 지나가는 홉마다 멈춰서
// "지금 이건 사용자가 보는 화면인가, 브라우저가 자동으로 따라가는 중인가,
// 아니면 서버끼리의 대화인가"를 보여준다. lab_step 쿠키/쿼리는 랩 전용이다.
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"oauth-lab/internal/lab"
	"oauth-lab/internal/store"
)

const (
	selfURL      = "http://127.0.0.1:9002"
	asURL        = "http://127.0.0.1:9000"
	rsURL        = "http://127.0.0.1:9001"
	clientID     = "demo-app"
	clientSecret = "demo-secret"
	redirectURI  = selfURL + "/callback"
	scope        = "openid profile notes:read"
)

type session struct {
	AccessToken string
	Scope       string
	Subject     string // id_token 에서 검증해 얻은 "누구" (OIDC)
}

// TokenPreview 는 화면 표시용으로 토큰 앞부분만 보여준다 (JWT 는 길다).
func (s *session) TokenPreview() string {
	if len(s.AccessToken) <= 48 {
		return s.AccessToken
	}
	return s.AccessToken[:48] + "…(생략)"
}

var (
	mu       sync.Mutex
	sessions = map[string]*session{}
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleHome)
	mux.HandleFunc("/login", handleLogin)
	mux.HandleFunc("/callback", handleCallback)
	mux.HandleFunc("/callback/exchange", handleExchange)
	mux.HandleFunc("/logout", handleLogout)
	mux.HandleFunc("/mode", handleMode)

	log.Printf("[APP] listening on %s", selfURL)
	log.Fatal(http.ListenAndServe("127.0.0.1:9002", logging("APP", mux)))
}

// ---------------------------------------------------------------------------
// 스텝 모드
// ---------------------------------------------------------------------------

// stepMode 는 기본 켜짐이다. 끄면 원래 OAuth 처럼 홉이 자동으로 흘러간다.
func stepMode(r *http.Request) bool {
	c, err := r.Cookie("lab_step")
	return err != nil || c.Value != "0"
}

func handleMode(w http.ResponseWriter, r *http.Request) {
	v := "1"
	if r.URL.Query().Get("step") == "0" {
		v = "0"
	}
	http.SetCookie(w, &http.Cookie{Name: "lab_step", Value: v, Path: "/", MaxAge: 30 * 24 * 3600})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ---------------------------------------------------------------------------
// 화면들
// ---------------------------------------------------------------------------

var homeTmpl = template.Must(template.New("home").Parse(`<!doctype html>
<meta charset="utf-8"><title>데모 앱</title>
<style>` + lab.CSS + `</style>
{{.Banner}}
<nav>{{if .Step}}<a href="/mode?step=0">스텝 모드 끄기 (실제처럼 한 번에)</a>
{{else}}<a href="/mode?step=1">스텝 모드 켜기 (홉마다 멈추기)</a>{{end}}</nav>
{{.BadgeHTML}}
<h1>데모 앱 (:9002)</h1>
{{if not .Session}}
  <p>로그인하지 않았습니다.</p>
  <p><a class="btn" href="/login">인가서버로 로그인</a></p>
{{else}}
  <p>로그인 완료.{{if .Session.Subject}} id_token 으로 확인한 사용자: <b>{{.Session.Subject}}</b>{{end}}</p>
  <p>access token (scope: <code>{{.Session.Scope}}</code>)</p>
  <pre>{{.Session.TokenPreview}}</pre>
  <h2>리소스서버 호출 (:9001)</h2>
  {{range .Calls}}<p><b>GET {{.Path}}</b> → {{.Status}}</p><pre>{{.Body}}</pre>{{end}}
  <p><a href="/logout">로그아웃</a></p>
{{end}}
`))

type call struct{ Path, Status, Body string }

type homeData struct {
	Step    bool
	Session *session
	Calls   []call
}

func (homeData) BadgeHTML() template.HTML { return lab.Badge(lab.KindUserView) }
func (homeData) Banner() template.HTML    { return lab.ServerBanner("9002") }

func handleHome(w http.ResponseWriter, r *http.Request) {
	s := currentSession(r)
	data := homeData{Step: stepMode(r), Session: s}

	if s != nil {
		for _, path := range []string{"/me", "/notes"} {
			status, body := callResource(s.AccessToken, path)
			data.Calls = append(data.Calls, call{path, status, body})
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = homeTmpl.Execute(w, data)
}

// handleLogin: front channel 시작. 브라우저를 인가서버로 보낸다.
func handleLogin(w http.ResponseWriter, r *http.Request) {
	step := stepMode(r)

	u, _ := url.Parse(asURL + "/authorize")
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", scope)
	// [FIXED-1] CSRF 방어: 예측 불가능한 state 를 만들어 브라우저 쿠키에 저장해두고,
	// 같은 값을 /authorize 에 실어 보낸다. 콜백에서 이 둘이 일치할 때만 code 를 받아들인다.
	state := store.RandString(16)
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", Value: state, Path: "/", HttpOnly: true, MaxAge: 300})
	q.Set("state", state)

	// [FIXED-4] PKCE: 일회용 verifier 를 만들어 쿠키에 보관하고, 그 해시(challenge)만 보낸다.
	// challenge 는 URL 에 실려 다녀도 안전하다 — 원본 verifier 없이는 되돌릴 수 없으니까(SHA-256).
	verifier := store.RandString(48)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	http.SetCookie(w, &http.Cookie{Name: "pkce_verifier", Value: verifier, Path: "/", HttpOnly: true, MaxAge: 300})
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")

	// [OIDC] nonce: 이 로그인 요청과 돌아올 id_token 을 묶는 값. replay 방지.
	nonce := store.RandString(16)
	http.SetCookie(w, &http.Cookie{Name: "oidc_nonce", Value: nonce, Path: "/", HttpOnly: true, MaxAge: 300})
	q.Set("nonce", nonce)

	if step {
		q.Set("lab_step", "1") // 랩 전용. 인가서버도 홉마다 멈추게 한다.
	}
	u.RawQuery = q.Encode()

	if !step {
		http.Redirect(w, r, u.String(), http.StatusFound)
		return
	}
	lab.RenderHop(w, lab.Hop{
		Port:        "9002",
		Step:        "① / ⑥  앱 → 브라우저",
		Kind:        lab.KindAutoRedirect,
		Title:       "앱이 브라우저를 인가서버로 떠민다",
		Explain:     `앱은 브라우저를 인가서버로 보내는 것 외엔 할 수 있는 게 없습니다. 아래가 곧 주소창에 나타날 URL 입니다.`,
		Params:      lab.QueryKV(u.String(), "response_type", "client_id", "redirect_uri", "scope", "state"),
		RawRequest:  "HTTP/1.1 302 Found\nLocation: " + u.String(),
		ContinueURL: u.String(), ContinueLabel: "브라우저가 따라간다 →",
	})
}

// handleCallback: 브라우저가 code 를 들고 돌아온다. 브라우저의 역할은 여기서 끝난다.
func handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		http.Error(w, "인가서버 에러: "+e+" — "+q.Get("error_description"), http.StatusBadRequest)
		return
	}
	code := q.Get("code")
	if code == "" {
		http.Error(w, "code 가 없습니다", http.StatusBadRequest)
		return
	}

	// [앱의 흔한 실수] "로그인 후 원래 보던 페이지로 돌려보내기" 를 next 파라미터로 구현했다.
	// next 값을 검증하지 않아서 open redirect 가 된다. 이 자체로는 앱 버그지만,
	// 인가서버가 redirect_uri 를 느슨하게(prefix) 검증하면 code 유출 경로가 완성된다.
	// → 그래서 인가서버의 redirect_uri "완전 일치" 가 이 실수까지 덮어준다 (스텝 4).
	if next := q.Get("next"); next != "" {
		http.Redirect(w, r, next+"?code="+code, http.StatusFound)
		return
	}

	// [FIXED-1] state 검증. "이 콜백이 정말 내가 시작한 로그인의 결과인가?"
	// 쿠키에 저장해둔 값과 URL 로 돌아온 값이 일치해야 한다. 공격자는 피해자 브라우저의
	// oauth_state 쿠키 값을 알 수 없으므로, 자기 code 를 흘려보내도 여기서 막힌다.
	if lab.Off("state") {
		// ./lab off state 로 방어를 끈 상태. 스텝 3의 공격이 성공한다.
		log.Printf("[APP] ⚠️  state 검증이 꺼져 있습니다 (./lab on state 로 켜세요)")
	} else {
		saved, err := r.Cookie("oauth_state")
		if err != nil || saved.Value == "" || saved.Value != q.Get("state") {
			http.Error(w, "잘못된 state — 내가 시작하지 않은 로그인입니다 (CSRF 차단)", http.StatusBadRequest)
			return
		}
	}
	// 한 번 쓴 state 는 즉시 폐기한다 (재사용 방지).
	http.SetCookie(w, &http.Cookie{Name: "oauth_state", Value: "", Path: "/", MaxAge: -1})
	log.Printf("[APP] code 수신: %s (state 검증 통과)", code)

	if !stepMode(r) {
		finishExchange(w, r, code, false)
		return
	}
	lab.RenderHop(w, lab.Hop{
		Port:        "9002",
		Step:        "④ / ⑥  브라우저 → 앱",
		Kind:        lab.KindAutoRedirect,
		Title:       "브라우저가 code 를 배달하고, 여기서 퇴장한다",
		Explain:     `브라우저의 역할은 여기까지입니다. 다음 홉부터는 앱 서버가 혼자 움직입니다.`,
		Params:      lab.QueryKV(selfURL+r.URL.RequestURI(), "code", "state"),
		RawRequest:  "GET " + r.URL.RequestURI() + " HTTP/1.1\nHost: 127.0.0.1:9002",
		ContinueURL: "/callback/exchange", ContinueLabel: "앱 서버가 백채널로 토큰을 받아온다 →",
		PostFields: []lab.KV{{K: "code", V: code}},
	})
}

// handleExchange: back channel. 브라우저는 이 요청의 존재조차 모른다.
func handleExchange(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	finishExchange(w, r, r.PostForm.Get("code"), stepMode(r))
}

func finishExchange(w http.ResponseWriter, r *http.Request, code string, step bool) {
	verifier := ""
	if c, err := r.Cookie("pkce_verifier"); err == nil {
		verifier = c.Value
	}
	tok, rawReq, rawResp, err := exchangeCode(code, verifier)
	if err != nil {
		http.Error(w, "토큰 교환 실패: "+err.Error(), http.StatusBadGateway)
		return
	}

	// [OIDC] id_token 을 검증해 "누구인지" 를 얻는다. /me 를 호출할 필요가 없다.
	subject := ""
	if tok.IDToken != "" {
		nonce := ""
		if c, err := r.Cookie("oidc_nonce"); err == nil {
			nonce = c.Value
		}
		http.SetCookie(w, &http.Cookie{Name: "oidc_nonce", Value: "", Path: "/", MaxAge: -1})
		sub, verr := verifyIDToken(tok.IDToken, nonce)
		if verr != nil {
			http.Error(w, "id_token 검증 실패: "+verr.Error(), http.StatusBadGateway)
			return
		}
		subject = sub
	}

	sid := store.RandString(16)
	mu.Lock()
	sessions[sid] = &session{AccessToken: tok.AccessToken, Scope: tok.Scope, Subject: subject}
	mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: sid, Path: "/", HttpOnly: true})

	if !step {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	lab.RenderHop(w, lab.Hop{
		Port:        "9002",
		Step:        "⑤ / ⑥  앱 서버 → 인가서버",
		Kind:        lab.KindBackChannel,
		Title:       "백채널: code 를 access token 으로 바꾼다",
		Explain:     `앱 서버가 인가서버에 직접 보낸 요청입니다. 브라우저를 거치지 않습니다.`,
		RawRequest:  rawReq,
		RawResponse: rawResp,
		ContinueURL: "/", ContinueLabel: "결과 화면으로 →",
	})
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope"`
	IDToken     string `json:"id_token"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

// exchangeCode 는 토큰 교환을 수행하고, 화면에 보여줄 원문 요청/응답도 함께 돌려준다.
func exchangeCode(code, verifier string) (tr *tokenResponse, rawReq, rawResp string, err error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	rawReq = "POST /token HTTP/1.1\nHost: 127.0.0.1:9000\n" +
		"Content-Type: application/x-www-form-urlencoded\n\n" +
		strings.ReplaceAll(form.Encode(), "&", "\n&")

	resp, err := http.PostForm(asURL+"/token", form)
	if err != nil {
		return nil, rawReq, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	rawResp = fmt.Sprintf("HTTP/1.1 %s\nContent-Type: %s\n\n%s",
		resp.Status, resp.Header.Get("Content-Type"), strings.TrimSpace(string(body)))
	log.Printf("[APP] /token 응답 %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))

	var out tokenResponse
	if jsonErr := json.Unmarshal(body, &out); jsonErr != nil {
		return nil, rawReq, rawResp, fmt.Errorf("JSON 파싱 실패: %s", body)
	}
	if out.Error != "" {
		return nil, rawReq, rawResp, fmt.Errorf("%s: %s", out.Error, out.ErrorDesc)
	}
	return &out, rawReq, rawResp, nil
}

func callResource(token, path string) (status, body string) {
	req, _ := http.NewRequest(http.MethodGet, rsURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "연결 실패", err.Error() + "\n(리소스서버는 스텝 2에서 만듭니다: make rs)"
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.Status, strings.TrimSpace(string(b))
}

func currentSession(r *http.Request) *session {
	c, err := r.Cookie("sid")
	if err != nil {
		return nil
	}
	mu.Lock()
	defer mu.Unlock()
	return sessions[c.Value]
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("sid"); err == nil {
		mu.Lock()
		delete(sessions, c.Value)
		mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "sid", Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
