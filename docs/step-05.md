# 스텝 5 — 공격 #3: code 가로채기, 그리고 PKCE

## 문제: code 가 새면 끝이다 (특히 public client)

스텝 4에서 redirect_uri 완전 일치로 code 유출 경로 하나를 막았다. 하지만 code 는 다른 데로도 샌다:
- 모바일 커스텀 스킴 하이재킹 (다른 앱이 같은 스킴 등록)
- 로그, 프록시, 브라우저 히스토리

**public client(secret 없음)** 는 code 만 있으면 누구나 토큰으로 바꾼다. secret 이라는 관문이 없으니까.
스텝 3의 자체 로그인 데모에 쓴 `public-app` 이 그 예다.

## PKCE (RFC 7636, S256)

secret 을 미리 심어두는 대신, **매 로그인마다 일회용 secret 을 즉석에서 만든다.**

1. 앱: `code_verifier` = 랜덤 문자열 (앱만 안다, 쿠키에 보관)
2. 앱: `code_challenge` = BASE64URL(SHA256(verifier)) — 이것만 `/authorize` 로 보낸다
3. AS: challenge 를 code 에 저장
4. 앱: `/token` 에 원본 `code_verifier` 를 보낸다
5. AS: verifier 를 다시 해시해서 저장해둔 challenge 와 비교. 다르면 거부.

challenge 는 URL 에 실려 다녀도 안전하다 — SHA-256 은 되돌릴 수 없으니 challenge 로 verifier 를 못 구한다.
**code 를 훔쳐도 verifier(앱 쿠키에만 있음)가 없으면 토큰을 못 받는다.**

## 직접 확인 (openssl 로 손계산)

```bash
V=$(cat /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | head -c 64)
C=$(printf %s "$V" | openssl dgst -binary -sha256 | openssl base64 | tr '+/' '-_' | tr -d '=')
echo "verifier=$V"; echo "challenge=$C"

# challenge 로 code 받기
CODE=$(curl -s -o /dev/null -D - -X POST http://127.0.0.1:9000/approve \
  -d username=alice -d client_id=demo-app -d 'redirect_uri=http://127.0.0.1:9002/callback' \
  -d 'scope=profile notes:read' -d "code_challenge=$C" -d 'code_challenge_method=S256' \
  | grep -i '^location:' | tr -d '\r' | sed -n 's/.*code=\([^&]*\).*/\1/p')

# ① 올바른 verifier → 토큰
curl -s -X POST http://127.0.0.1:9000/token -d grant_type=authorization_code -d code=$CODE \
  -d client_id=demo-app -d client_secret=demo-secret -d "code_verifier=$V" | jq .access_token

# ② 훔친 code + 틀린 verifier → invalid_grant
curl -s -X POST http://127.0.0.1:9000/token -d grant_type=authorization_code -d code=$CODE \
  -d client_id=demo-app -d client_secret=demo-secret -d "code_verifier=WRONG" | jq .error_description
```

```
①  dLF3xELeY-SwHSZ3...           ← 성공
②  "code_verifier 불일치 ..."    ← 훔쳐도 못 씀
```

## 토글

```bash
./lab off pkce    # challenge 없이 통과, verifier 검증 안 함
./lab on  pkce    # challenge 필수(S256), verifier 검증
```

## state vs PKCE — 뭐가 다른가

| | 막는 것 | 어떻게 |
|---|---|---|
| state | 로그인 CSRF ("내가 시작한 로그인인가") | 콜백의 state == 내 쿠키 |
| PKCE | code 가로채기 ("이 토큰요청이 그 authorize와 같은 세션인가") | verifier 해시 == 저장된 challenge |

둘 다 "앱만 아는 값을 브라우저 쿠키에 두고 대조" 라는 뼈대는 같다. 방어하는 층위가 다를 뿐.

## 왜 2.1 은 plain 을 빼고 S256 만 남겼나

`plain` 메서드는 challenge = verifier (해시 안 함). 이러면 challenge 가 URL 에서 새는 순간
verifier 도 그대로 노출돼 PKCE 가 무의미해진다. 그래서 2.1 은 S256 만 인정한다.

## 코드에서 볼 곳

| 무엇 | 어디 |
|---|---|
| verifier 생성·challenge 전송 | `cmd/client/main.go` `handleLogin` `[FIXED-4]` |
| verifier 를 교환에 포함 | `cmd/client/main.go` `finishExchange` / `exchangeCode` |
| challenge 필수 검증 | `cmd/authserver/main.go` `handleAuthorize` |
| verifier 해시 대조 | `cmd/authserver/main.go` `grantAuthorizationCode` |

## 내가 채울 칸

- confidential client(secret 있음)도 2.1 은 PKCE 를 요구한다. secret 이 있는데 왜 또 필요한가? →
- challenge 를 URL 로 보내도 안전한 이유를 한 문장으로 →
- PKCE 가 있으면 state 는 필요 없다는 주장 — 맞나 틀리나? (힌트: 둘의 저장 위치와 검증 시점) →
