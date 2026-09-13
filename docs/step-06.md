# 스텝 6 — opaque 에서 JWT 로, 그리고 검증의 함정

## 두 가지 토큰 검증 방식

| | opaque (스텝 2~5) | JWT (스텝 6) |
|---|---|---|
| 토큰 모양 | 랜덤 문자열 | `header.payload.signature` (점 2개) |
| RS 가 검증하는 법 | AS 에 introspection **왕복** | 서명만 **로컬 검증** (왕복 없음) |
| AS 의존 | 매 요청마다 필요 | JWKS 한 번만 받으면 됨 |
| 즉시 회수 | 가능 (AS 가 상태 보유) | **불가** (만료까지 유효) ← 스텝 7 |

`./lab off jwt` 로 opaque(introspection) 로 되돌릴 수 있다. 기본은 JWT.

## JWT 뜯어보기

```bash
TOK=... # /token 으로 받은 access_token
echo "$TOK" | cut -d. -f2 | base64 -D | jq   # payload 는 누구나 읽는다
```
```json
{"iss":"http://127.0.0.1:9000","sub":"alice","aud":"http://127.0.0.1:9001",
 "scope":"profile notes:read","iat":..., "exp":...}
```

> **payload 는 암호화가 아니라 서명이다.** base64 라 누구나 읽는다 → 민감정보를 넣으면 안 된다.
> 서명은 "내용이 위조되지 않았음" 만 보장한다.

JWKS (공개키):
```bash
curl -s http://127.0.0.1:9000/.well-known/jwks.json | jq
```
RS 는 여기서 `kid` 로 공개키를 골라 서명을 검증한다. AS 와 secret 을 공유하지 않는다.

## 공격 A — alg:none (서명 우회)

서명 없는 위조 토큰을 만든다:
```bash
H=$(printf '{"alg":"none","typ":"JWT"}' | base64 | tr '+/' '-_' | tr -d '=')
P=$(printf '{"iss":"http://127.0.0.1:9000","sub":"admin","aud":"http://127.0.0.1:9001","scope":"profile notes:read","exp":9999999999}' | base64 | tr '+/' '-_' | tr -d '=')
FAKE="$H.$P."      # 서명 자리가 비어 있다

./lab on  algnone; curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $FAKE" http://127.0.0.1:9001/notes  # 401
./lab off algnone; curl -s -H "Authorization: Bearer $FAKE" http://127.0.0.1:9001/notes  # admin 으로 통과!
```

**왜 위험한가:** RS 가 header 의 `alg` 를 곧이곧대로 믿으면, 공격자가 `alg:none` 으로 바꿔 서명 검사를 통째로 건너뛴다. → 방어: **alg 화이트리스트(RS256 만)**. header 가 시키는 대로 하지 않는다.

## 공격 B — aud 누락 (남의 토큰 재사용)

다른 서비스(:9005)용으로 **정상 발급된** 토큰을 이 RS(:9001)에 들이민다:
```bash
# resource=:9005 로 aud 가 :9005 인 토큰을 받는다 (서명은 진짜)
OTHER=$(... -d 'resource=http://127.0.0.1:9005' | jq -r .access_token)

./lab on  aud; curl ... -H "Authorization: Bearer $OTHER" http://127.0.0.1:9001/notes  # 401
./lab off aud; curl ... -H "Authorization: Bearer $OTHER" http://127.0.0.1:9001/notes  # 200 통과!
```

**왜 위험한가:** 서명은 완벽히 유효하다. 하지만 이 토큰은 :9005 용이다. aud 를 안 보면,
:9005 를 뚫은 공격자(혹은 :9005 자신)가 그 토큰으로 :9001 까지 넘본다. → 방어: **aud == 나인지 검증.**

## 검증 필수 항목 (순서대로)

1. **alg** 화이트리스트 → 서명 우회 차단
2. **서명** (JWKS 공개키로)
3. **exp** 만료
4. **iss** 발급자
5. **aud** 수신자 = 나

하나라도 빠지면 구멍이다. 가장 자주 빠뜨리는 게 **aud**.

## 코드에서 볼 곳

| 무엇 | 어디 |
|---|---|
| JWT 서명 (RS256) | `cmd/authserver/jwt.go` `signJWT` |
| JWKS 노출 | `cmd/authserver/jwt.go` `handleJWKS` |
| JWT 검증 전체 | `cmd/resource/jwt.go` `verifyJWT` / `claimsToIntrospection` |
| alg 화이트리스트 | `cmd/resource/jwt.go` (`algnone` 토글) |
| aud 검증 | `cmd/resource/jwt.go` (`aud` 토글) |

## 내가 채울 칸

- JWT payload 에 사용자 비밀번호를 넣으면 왜 안 되나? (base64 를 떠올려라) →
- introspection 은 즉시 회수가 되는데 JWT 로컬검증은 왜 안 되나? →
- alg 를 RS256 화이트리스트로 고정하는 게, 왜 "alg:none 거부" 보다 넓은 방어인가? (HS256 혼동 공격) →
