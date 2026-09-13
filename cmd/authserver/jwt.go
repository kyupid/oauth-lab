package main

// JWT 서명 — stdlib 만으로 직접 구현한다. 라이브러리가 뒤에서 뭘 하는지 보이도록.
//
// JWT = base64url(header) . base64url(payload) . base64url(signature)
// 서명은 RS256 = RSASSA-PKCS1-v1_5(SHA-256). AS 는 개인키로 서명하고,
// RS 는 JWKS 로 받은 공개키로 검증한다. 서로 secret 을 공유할 필요가 없다.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"time"
)

var (
	signKey *rsa.PrivateKey
	keyID   string
)

func initSigningKey() {
	var err error
	signKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	// kid = 공개키 지문 (앞 16바이트). RS 가 여러 키 중 어느 것으로 검증할지 고르는 데 쓴다.
	sum := sha256.Sum256(signKey.N.Bytes())
	keyID = base64.RawURLEncoding.EncodeToString(sum[:12])
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signJWT 는 claims 를 RS256 JWT 로 만든다.
func signJWT(claims map[string]any) string {
	header := map[string]any{"alg": "RS256", "typ": "JWT", "kid": keyID}
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(claims)
	signingInput := b64(hb) + "." + b64(pb)

	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, signKey, crypto.SHA256, digest[:])
	if err != nil {
		panic(err)
	}
	return signingInput + "." + b64(sig)
}

// accessTokenJWT 는 스텝 6의 access token 이다. opaque 랜덤 대신 이걸 발급한다.
func accessTokenJWT(sub, scope, audience string) string {
	now := time.Now()
	return signJWT(map[string]any{
		"iss":   issuer,
		"sub":   sub,
		"aud":   audience, // 이 토큰을 쓸 리소스서버. RS 가 이걸 검증해야 한다 (스텝 6 공격 지점)
		"scope": scope,
		"iat":   now.Unix(),
		"exp":   now.Add(10 * time.Minute).Unix(),
	})
}

// handleJWKS 는 공개키를 JWKS 형식으로 노출한다 (RFC 7517).
// RS 는 여기서 공개키를 받아 캐싱해두고 로컬에서 검증한다 — AS 에 매번 물어볼 필요가 없다.
func handleJWKS(w http.ResponseWriter, r *http.Request) {
	pub := signKey.PublicKey
	// n(모듈러스), e(지수) 를 base64url 로. 이게 공개키의 전부다.
	eBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(eBuf, uint64(pub.E))
	eBuf = trimLeadingZeros(eBuf)

	writeJSON(w, http.StatusOK, map[string]any{
		"keys": []map[string]any{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": keyID,
			"n":   b64(pub.N.Bytes()),
			"e":   b64(eBuf),
		}},
	})
}

func trimLeadingZeros(b []byte) []byte {
	i := 0
	for i < len(b)-1 && b[i] == 0 {
		i++
	}
	return b[i:]
}
