package lab

import (
	"html/template"
	"net/http"
)

// CSS 는 랩 전체가 공유하는 스타일이다. 홉의 성격을 색으로 구분한다.
const CSS = `
:root{--user:#0a7c2f;--auto:#1f6feb;--back:#3d3d3d;--bg:#fff;--fg:#111;--mut:#666;--line:#ddd}
@media (prefers-color-scheme:dark){:root{--user:#4ade80;--auto:#6ea8fe;--back:#bbb;--bg:#14161a;--fg:#e8e8e8;--mut:#9aa0a6;--line:#333}}
*{box-sizing:border-box}
body{font-family:ui-sans-serif,system-ui,-apple-system,"Apple SD Gothic Neo",sans-serif;
  max-width:46rem;margin:0 auto;padding:2rem 1.25rem 4rem;line-height:1.65;background:var(--bg);color:var(--fg)}
h1{font-size:1.4rem;margin:.2rem 0 1rem}
h2{font-size:1.05rem;margin:2rem 0 .5rem}
code{background:rgba(127,127,127,.16);padding:.1rem .35rem;border-radius:3px;font-size:.9em}
pre{background:rgba(127,127,127,.12);padding:.9rem 1rem;border-radius:8px;overflow-x:auto;
  font-size:.82rem;line-height:1.5;white-space:pre-wrap;word-break:break-all;border:1px solid var(--line)}
table{border-collapse:collapse;width:100%;font-size:.85rem;margin:.5rem 0}
td{border-bottom:1px solid var(--line);padding:.35rem .5rem;vertical-align:top}
td:first-child{color:var(--mut);white-space:nowrap;width:11rem;font-family:ui-monospace,monospace}
td:last-child{font-family:ui-monospace,monospace;word-break:break-all}
.badge{display:inline-block;font-size:.78rem;font-weight:600;padding:.2rem .6rem;border-radius:999px;
  border:1px solid currentColor;margin-bottom:.75rem}
.k-user-view,.k-user-action{color:var(--user)}
.k-auto-redirect{color:var(--auto)}
.k-back-channel,.k-resource-call{color:var(--back)}
.hint{color:var(--mut);font-size:.88rem;border-left:3px solid var(--line);padding-left:.9rem;margin:1rem 0}
.btn{display:inline-block;padding:.6rem 1.1rem;border-radius:8px;text-decoration:none;font-weight:600;
  border:0;font-size:.95rem;cursor:pointer;background:var(--fg);color:var(--bg)}
.step{color:var(--mut);font-size:.85rem;letter-spacing:.04em}
nav{font-size:.85rem;margin-bottom:1.5rem}
nav a{color:var(--mut);margin-right:1rem}
`

// Badge 는 홉 성격을 사람 말로 바꾼다. 이 문구가 이 랩에서 제일 중요한 부분이다.
func Badge(kind string) template.HTML {
	label := map[string]string{
		KindUserAction:   "🖱 사용자가 직접 누름",
		KindUserView:     "👁 사용자가 실제로 보는 화면",
		KindAutoRedirect: "↪︎ 브라우저가 자동으로 따라가는 홉 — 원래는 사용자가 못 느낌",
		KindBackChannel:  "🔒 서버끼리 (브라우저 밖) — 사용자는 절대 못 봄",
		KindResource:     "📦 앱 서버 → 리소스서버 (브라우저 밖)",
	}[kind]
	if label == "" {
		label = kind
	}
	return template.HTML(`<span class="badge k-` + kind + `">` + label + `</span>`)
}

// Hop 은 "원래는 눈 깜짝할 새 지나갔을 한 번의 HTTP 홉"을 멈춰 세운 화면이다.
type Hop struct {
	Port          string // 이 홉 화면이 어느 서버에서 렌더되는가 (배너용)
	Step          string // "① / ⑥" 같은 진행 표시
	Kind          string
	Title         string
	Explain       template.HTML
	Params        []KV
	RawRequest    string
	RawResponse   string
	Hint          template.HTML
	ContinueURL   string
	ContinueLabel string
	PostFields    []KV // 있으면 링크 대신 POST 폼으로 렌더
}

func (h Hop) BadgeHTML() template.HTML  { return Badge(h.Kind) }
func (h Hop) BannerHTML() template.HTML { return ServerBanner(h.Port) }

var hopTmpl = template.Must(template.New("hop").Parse(`<!doctype html>
<meta charset="utf-8"><title>{{.Step}} {{.Title}}</title>
<style>` + CSS + `</style>
{{.BannerHTML}}
<nav><a href="/">앱 홈</a></nav>
<p class="step">{{.Step}}</p>
{{.BadgeHTML}}
<h1>{{.Title}}</h1>
<div>{{.Explain}}</div>
{{if .Params}}<h2>실려 가는 값</h2><table>
{{range .Params}}<tr><td>{{.K}}</td><td>{{.V}}</td></tr>{{end}}
</table>{{end}}
{{if .RawRequest}}<h2>요청</h2><pre>{{.RawRequest}}</pre>{{end}}
{{if .RawResponse}}<h2>응답</h2><pre>{{.RawResponse}}</pre>{{end}}
{{if .Hint}}<div class="hint">{{.Hint}}</div>{{end}}
{{if .PostFields}}
<form method="POST" action="{{.ContinueURL}}">
  {{range .PostFields}}<input type="hidden" name="{{.K}}" value="{{.V}}">{{end}}
  <p><button class="btn" type="submit">{{.ContinueLabel}}</button></p>
</form>
{{else if .ContinueURL}}
<p><a class="btn" href="{{.ContinueURL}}">{{.ContinueLabel}}</a></p>
{{end}}
`))

// RenderHop 은 홉 화면을 그린다.
func RenderHop(w http.ResponseWriter, h Hop) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = hopTmpl.Execute(w, h)
}

// serverInfo 는 포트별 (색, 이름, 역할) 이다.
var serverInfo = map[string][3]string{
	"9000": {"#7c3aed", "인가서버", "로그인·동의·토큰 발급 (Authorization Server)"},
	"9001": {"#0891b2", "리소스서버", "보호된 데이터 (Resource Server)"},
	"9002": {"#0a7c2f", "앱", "내가 쓰는 클라이언트 (Client)"},
	"9003": {"#c0202f", "공격자 사이트", "⚠ 이건 나쁜 놈이다"},
}

// ServerBanner 는 각 서버 화면 최상단에 고정으로 붙는 큰 식별 배너다.
// 포트가 헷갈리지 않도록 서버마다 색과 이름을 다르게 준다.
func ServerBanner(port string) template.HTML {
	info, ok := serverInfo[port]
	if !ok {
		info = [3]string{"#333", "서버", ""}
	}
	return template.HTML(`<div style="position:sticky;top:0;z-index:99;margin:-2rem -1.25rem 1.5rem;
		padding:.6rem 1.25rem;background:` + info[0] + `;color:#fff;
		display:flex;gap:.6rem;align-items:baseline;box-shadow:0 2px 8px rgba(0,0,0,.15)">
		<span style="font-size:1.15rem;font-weight:800">:` + port + `</span>
		<span style="font-size:1.05rem;font-weight:700">` + info[1] + `</span>
		<span style="font-weight:400;opacity:.9;font-size:.85rem">` + info[2] + `</span>
	</div>`)
}
