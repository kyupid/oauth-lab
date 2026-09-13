// Package store 는 학습용 인메모리 저장소다. 영속성도, 동시성 최적화도 없다.
package store

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// Client 는 인가서버에 사전 등록된 클라이언트 앱이다.
type Client struct {
	ID          string
	Secret      string // 공개 클라이언트면 ""
	RedirectURI string // 등록된 redirect_uri (스텝 4에서 "완전 일치"로 바뀐다)
}

// AuthCode 는 /authorize 가 발급하고 /token 이 소비하는 1회성 인가코드다.
type AuthCode struct {
	Code        string
	ClientID    string
	RedirectURI string
	Subject     string // 로그인한 사용자
	Scope       string
	CreatedAt   time.Time
	Used        bool
	// PKCE — 스텝 5에서 채운다
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string // OIDC
	Resource            string // RFC 8707 — 이 code 로 받을 토큰의 대상(aud)
}

// Token 은 access token 이다. 스텝 1~5 에서는 opaque 랜덤 문자열이다.
type Token struct {
	Value     string
	ClientID  string
	Subject   string
	Scope     string
	ExpiresAt time.Time
	FromCode  string // 어느 인가코드에서 나왔는지 (스텝 4 코드 재사용 탐지용)
}

// RefreshToken 은 access token 을 갱신하는 데 쓴다. opaque 이고 AS 가 상태를 쥔다.
// Family 는 "하나의 로그인에서 파생된 refresh 들" 을 묶는다 — 회전하면 같은 Family 가 이어진다.
// 재사용이 감지되면 그 Family 전체를 폐기한다 (탈취 신호).
type RefreshToken struct {
	Value     string
	Family    string
	ClientID  string
	Subject   string
	Scope     string
	Used      bool // 이미 갱신에 쓰였나 (회전 후 true)
	ExpiresAt time.Time
}

// Memory 는 전체 저장소다.
type Memory struct {
	mu      sync.Mutex
	clients map[string]Client
	codes   map[string]*AuthCode
	tokens  map[string]*Token
	refresh map[string]*RefreshToken
}

func New() *Memory {
	return &Memory{
		clients: map[string]Client{},
		codes:   map[string]*AuthCode{},
		tokens:  map[string]*Token{},
		refresh: map[string]*RefreshToken{},
	}
}

func (m *Memory) RegisterClient(c Client) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[c.ID] = c
}

func (m *Memory) Client(id string) (Client, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[id]
	return c, ok
}

func (m *Memory) SaveCode(c *AuthCode) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[c.Code] = c
}

func (m *Memory) Code(code string) (*AuthCode, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[code]
	return c, ok
}

func (m *Memory) SaveToken(t *Token) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[t.Value] = t
}

func (m *Memory) Token(v string) (*Token, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[v]
	return t, ok
}

// RevokeTokensFromCode 는 특정 인가코드에서 발급된 모든 access token 을 폐기한다.
// code 재사용이 감지되면(= 탈취 신호) 그 code 로 이미 나간 토큰까지 무효화한다.
func (m *Memory) RevokeTokensFromCode(code string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for v, t := range m.tokens {
		if t.FromCode == code {
			delete(m.tokens, v)
			n++
		}
	}
	return n
}

// RandString 은 URL-safe 랜덤 문자열을 만든다. code, token, state 모두 여기서 나온다.
func RandString(nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// --- refresh token ---

func (m *Memory) SaveRefresh(t *RefreshToken) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.refresh[t.Value] = t
}

func (m *Memory) Refresh(v string) (*RefreshToken, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.refresh[v]
	return t, ok
}

// RevokeFamily 는 한 Family 의 refresh 를 전부 폐기하고, 그 Family 에서 나온 access 토큰도 지운다.
// refresh 재사용(=탈취)이 감지되면 호출한다.
func (m *Memory) RevokeFamily(family string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for v, t := range m.refresh {
		if t.Family == family {
			delete(m.refresh, v)
			n++
		}
	}
	return n
}
