package main

// id_token 검증 — 앱이 "누구인지" 를 확인하는 곳. (RS 의 access token 검증과 목적이 다르다.)
//
// 앱이 반드시 봐야 할 것:
//   - 서명 (AS 의 JWKS 공개키)
//   - iss = 우리가 아는 AS
//   - aud = 나(clientID). 남의 앱용 id_token 을 들고 오는 걸 막는다.
//   - nonce = 내가 보낸 값. replay 를 막는다.
//   - exp

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
	"time"
)

func verifyIDToken(idToken, expectedNonce string) (string, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", errors.New("id_token 형식 오류")
	}
	var header struct{ Alg, Kid string }
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	json.Unmarshal(hb, &header)
	if header.Alg != "RS256" { // alg 화이트리스트 (스텝 6 교훈)
		return "", fmt.Errorf("허용되지 않은 alg: %s", header.Alg)
	}

	pub, err := fetchKey(header.Kid)
	if err != nil {
		return "", err
	}
	signingInput := parts[0] + "." + parts[1]
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return "", errors.New("서명 검증 실패")
	}

	var c struct {
		Iss, Sub, Aud, Nonce string
		Exp                  int64
	}
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	json.Unmarshal(pb, &c)

	if c.Iss != asURL {
		return "", fmt.Errorf("iss 불일치: %s", c.Iss)
	}
	if c.Aud != clientID { // 이 id_token 이 정말 "나(앱)" 앞으로 발급됐나
		return "", fmt.Errorf("aud 가 내가 아니다: %s", c.Aud)
	}
	if expectedNonce != "" && c.Nonce != expectedNonce { // 내가 시작한 로그인인가
		return "", errors.New("nonce 불일치 (replay 의심)")
	}
	if time.Now().Unix() > c.Exp {
		return "", errors.New("만료된 id_token")
	}
	return c.Sub, nil
}

func fetchKey(kid string) (*rsa.PublicKey, error) {
	resp, err := http.Get(asURL + "/.well-known/jwks.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var set struct {
		Keys []struct{ Kid, N, E string }
	}
	json.NewDecoder(resp.Body).Decode(&set)
	for _, k := range set.Keys {
		if k.Kid != kid {
			continue
		}
		nb, _ := base64.RawURLEncoding.DecodeString(k.N)
		eb, _ := base64.RawURLEncoding.DecodeString(k.E)
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}, nil
	}
	return nil, fmt.Errorf("kid %s 없음", kid)
}
