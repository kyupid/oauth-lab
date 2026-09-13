package main

// JWT 로컬 검증 — stdlib 만으로. RS 는 AS 의 JWKS(공개키)를 받아 캐싱해두고
// 매 요청마다 AS 에 물어보지 않고(=introspection 없이) 스스로 검증한다.
//
// 검증 순서가 중요하다. 특히:
//   - alg 화이트리스트: "alg":"none" 같은 걸 절대 믿으면 안 된다 (고전 취약점)
//   - aud 검증: 이 토큰이 "나(RS)" 앞으로 발급된 게 맞는지 (스텝 6 공격 지점)

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"oauth-lab/internal/lab"
)

type jwks struct {
	Keys []struct {
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
		Alg string `json:"alg"`
	} `json:"keys"`
}

var (
	keyCacheMu sync.Mutex
	keyCache   = map[string]*rsa.PublicKey{} // kid -> 공개키
)

// publicKey 는 kid 에 맞는 공개키를 돌려준다. 없으면 AS 의 JWKS 를 받아 캐싱한다.
func publicKey(kid string) (*rsa.PublicKey, error) {
	keyCacheMu.Lock()
	if k, ok := keyCache[kid]; ok {
		keyCacheMu.Unlock()
		return k, nil
	}
	keyCacheMu.Unlock()

	resp, err := http.Get(asURL + "/.well-known/jwks.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var set jwks
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return nil, err
	}
	keyCacheMu.Lock()
	defer keyCacheMu.Unlock()
	for _, k := range set.Keys {
		nb, _ := base64.RawURLEncoding.DecodeString(k.N)
		eb, _ := base64.RawURLEncoding.DecodeString(k.E)
		pub := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nb),
			E: int(new(big.Int).SetBytes(eb).Int64()),
		}
		keyCache[k.Kid] = pub
	}
	if k, ok := keyCache[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("kid %q 에 맞는 공개키 없음", kid)
}

type jwtClaims struct {
	Iss   string `json:"iss"`
	Sub   string `json:"sub"`
	Aud   string `json:"aud"`
	Scope string `json:"scope"`
	Exp   int64  `json:"exp"`
}

// looksLikeJWT: 점 두 개로 나뉘면 JWT 로 본다.
func looksLikeJWT(tok string) bool { return strings.Count(tok, ".") == 2 }

// verifyJWT 는 JWT 를 검증하고 claims 를 돌려준다. introspection 결과와 같은 모양으로 변환한다.
func verifyJWT(tok string) (introspection, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return introspection{}, errors.New("JWT 형식 아님")
	}
	headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return introspection{}, err
	}

	// [알고리즘 검증] alg 화이트리스트. "none" 이나 대칭키(HS256) 로 바꿔치기하는 공격을 막는다.
	if lab.Off("algnone") {
		// 방어 OFF: header 가 시키는 대로 믿는다 → alg:none 이면 서명 검사 자체를 건너뛴다 (취약!)
		if header.Alg == "none" {
			return claimsToIntrospection(parts[1], "none")
		}
	} else {
		if header.Alg != "RS256" {
			return introspection{}, fmt.Errorf("허용되지 않은 alg: %q (RS256 만 인정)", header.Alg)
		}
	}

	// [서명 검증]
	pub, err := publicKey(header.Kid)
	if err != nil {
		return introspection{}, err
	}
	signingInput := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return introspection{}, err
	}
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return introspection{}, errors.New("서명 검증 실패")
	}

	return claimsToIntrospection(parts[1], header.Alg)
}

func claimsToIntrospection(payloadB64, alg string) (introspection, error) {
	payloadJSON, _ := base64.RawURLEncoding.DecodeString(payloadB64)
	var c jwtClaims
	if err := json.Unmarshal(payloadJSON, &c); err != nil {
		return introspection{}, err
	}

	// [만료 검증]
	if time.Now().Unix() > c.Exp {
		return introspection{}, errors.New("만료된 토큰 (exp)")
	}
	// [발급자 검증]
	if c.Iss != asURL {
		return introspection{}, fmt.Errorf("믿지 않는 iss: %q", c.Iss)
	}
	// [수신자 검증] 이 토큰이 정말 "나(RS)" 앞으로 발급됐나?
	if lab.Off("aud") {
		// 방어 OFF: aud 를 안 본다 → 다른 서비스용 토큰도 통과한다 (취약!)
	} else {
		if c.Aud != selfURL() {
			return introspection{}, fmt.Errorf("이 토큰의 aud(%q)는 내가 아니다(%q)", c.Aud, selfURL())
		}
	}

	return introspection{
		Active: true, Scope: c.Scope, Sub: c.Sub, ClientID: "", Exp: c.Exp,
	}, nil
}
