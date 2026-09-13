// Package lab 은 학습용 표시 도구다. OAuth 스펙과는 무관하며, 오직
// "지금 이 화면이 사용자에게 보이는 것인가, 자동으로 지나가는 홉인가"를 드러내기 위해 존재한다.
package lab

import "net/http"

// Kind 는 한 HTTP 홉의 성격이다. 이 랩의 핵심 분류다.
const (
	// KindUserView: 사용자가 실제로 눈으로 보고 조작하는 화면.
	KindUserView = "user-view"
	// KindAutoRedirect: 브라우저가 302 를 받아 자동으로 따라가는 홉.
	// 사용자 눈에는 "아무 일도 없었던" 구간이지만 URL 에 값이 실려 다닌다.
	KindAutoRedirect = "auto-redirect"
	// KindBackChannel: 앱 서버 ↔ 인가서버. 브라우저를 거치지 않는다.
	// 사용자는 볼 수도, 가로챌 수도, 조작할 수도 없다.
	KindBackChannel = "back-channel"
	// KindResource: 앱 서버 → 리소스서버. 역시 브라우저 밖이다.
	KindResource = "resource-call"
	// KindUserAction: 사용자가 버튼/링크를 직접 누른 순간.
	KindUserAction = "user-action"
)

// KV 는 순서를 유지하는 파라미터 쌍이다.
type KV struct {
	K string
	V string
}

// QueryKV 는 URL 쿼리를 순서 있는 KV 로 바꾼다 (화면 표시용).
// keys 로 준 것을 먼저, 지정한 순서대로 놓는다.
func QueryKV(raw string, keys ...string) []KV {
	req, err := http.NewRequest("GET", raw, nil)
	if err != nil {
		return nil
	}
	q := req.URL.Query()
	var out []KV
	seen := map[string]bool{}
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			out = append(out, KV{k, v})
			seen[k] = true
		}
	}
	for k := range q {
		if !seen[k] && k != "lab_step" { // lab_step 은 랩 전용이라 표시하지 않는다
			out = append(out, KV{k, q.Get(k)})
		}
	}
	return out
}
