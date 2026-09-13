package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"time"
)

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// jsonError 는 /token 같은 back channel 에러다 (RFC 6749 §5.2).
func jsonError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// httpError 는 리다이렉트하면 안 되는 front channel 에러다.
// client_id 나 redirect_uri 자체가 의심스러우면 절대 리다이렉트하지 않는다 —
// 그랬다간 인가서버가 공격자의 open redirect 도구가 된다.
func httpError(w http.ResponseWriter, status int, code, desc string) {
	http.Error(w, code+": "+desc, status)
}

// redirectError 는 redirect_uri 는 신뢰할 수 있을 때의 front channel 에러다 (RFC 6749 §4.1.2.1).
func redirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		httpError(w, http.StatusBadRequest, "invalid_request", "redirect_uri 파싱 실패")
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// logging 은 오간 요청을 전부 찍는다. 이 로그를 보는 것이 이 랩의 절반이다.
func logging(tag string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("[%s] %s %s%s (%s)", tag, r.Method, r.URL.Path, rawQuery(r), time.Since(start).Round(time.Microsecond))
	})
}

func rawQuery(r *http.Request) string {
	if r.URL.RawQuery == "" {
		return ""
	}
	return "?" + r.URL.RawQuery
}
