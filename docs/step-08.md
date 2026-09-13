# 스텝 8 — OAuth 2.1 체크리스트로 내 서버 감사하기

2.1 은 새 프로토콜이 아니다. **2.0 + 보안 BCP 를 합치고, 위험한 것을 뺀 정리판**이다.
지금까지 만든 방어가 대부분 2.1 항목이다. 코드 근거로 감사한다.

## 2.1 준수 체크리스트

| 2.1 항목 | 내 서버 | 근거 (스텝) |
|---|---|---|
| 모든 클라이언트에 PKCE(S256) 필수 | ✅ | `handleAuthorize` challenge 필수 검증 (5) |
| redirect_uri 문자열 완전 일치 | ✅ | `handleAuthorize` exact match (4) |
| 인가코드 1회용 + 짧은 수명 | ✅ | `grantAuthorizationCode` (4) |
| refresh 회전 또는 sender-constrained | ✅ | `grantRefreshToken` 회전+재사용감지 (7) |
| Bearer 토큰 쿼리스트링 전달 금지 | ✅ | `requireScope` 400 (2) |
| **Implicit(response_type=token) 제거** | ✅ 제거 | 기본 거부, `./lab enable implicit` 로만 실습 |
| **ROPC(grant_type=password) 제거** | ✅ 제거 | 기본 거부, `./lab enable ropc` 로만 실습 |
| Discovery 문서 | ✅ | `/.well-known/oauth-authorization-server` |

## 제거된 것 ① — Implicit grant

**왜 있었나:** SPA 는 back channel(secret)이 없어서 `/token` 을 못 부른다고 여겼다.
그래서 `/authorize` 가 code 대신 **access token 을 바로** 줬다.

```bash
./lab enable implicit
# response_type=token → Location 확인
```
```
Location: http://127.0.0.1:9002/callback#access_token=eyJ...&token_type=Bearer
```

**왜 제거됐나:** access token 이 **URL fragment 로 직접** 나온다.
- 브라우저 히스토리·리퍼러에 토큰이 남는다
- JS 로 읽혀 XSS 에 그대로 노출
- code 단계가 없어 PKCE 로 보호할 수도 없다

**대체:** SPA 도 이제 Authorization Code + PKCE 를 쓴다 (back channel 없이도 PKCE 로 안전).

## 제거된 것 ② — ROPC (Resource Owner Password Credentials)

**왜 있었나:** "1st party 앱이면 우리 앱이니까 비번 직접 받아도 되지 않나?"

```bash
./lab enable ropc
curl ... -d grant_type=password -d username=alice -d password=hunter2 ...
```
서버 로그:
```
[AS] ⚠️ ROPC: 앱이 넘긴 사용자 비번을 직접 받음 user=alice pass=hunter2
```

**왜 제거됐나:** 앱이 사용자 비밀번호를 **직접 본다.** 이건 OAuth 의 존재 이유
("앱이 비번을 안 만지게 한다")를 정면으로 위반한다. MFA·소셜로그인·패스키와도 안 맞는다.

**대체:** 1st party 앱도 Authorization Code 플로우로. 비번은 오직 AS 만 본다.

## Discovery (RFC 8414)

지금까지 손으로 알던 엔드포인트들을 기계가 읽게 정리한 문서:
```bash
curl -s http://127.0.0.1:9000/.well-known/oauth-authorization-server | jq
```
`grant_types_supported` 에 password 가 없고, `code_challenge_methods_supported` 가 S256 뿐인 것 —
이 문서 자체가 "우리는 2.1 을 따른다" 는 선언이다.

## 핵심

2.1 의 방향은 하나다: **"선택지를 줄여서 안전한 기본값만 남긴다."**
plain PKCE, implicit, ROPC, 느슨한 redirect_uri, 긴 code — 다 "쓸 수는 있지만 위험한" 것들이었고,
2.1 은 그걸 아예 못 쓰게 만들었다.

## 코드에서 볼 곳

| 무엇 | 어디 |
|---|---|
| implicit / ROPC (제거 대상) | `cmd/authserver/legacy.go` |
| discovery | `cmd/authserver/legacy.go` `handleDiscovery` |
| 위험기능 토글 | `./lab enable\|disable implicit\|ropc` |

## 내가 채울 칸

- implicit 이 준 access token 은 왜 PKCE 로 보호할 수 없나? (code 단계가 없다는 점) →
- ROPC 를 "우리 1st party 앱인데 뭐 어때" 로 허용하면, 나중에 무엇이 불가능해지나? (MFA, 소셜로그인) →
- 2.1 이 "기능을 빼는" 방향으로 간 이유를, 지금까지 깨본 공격들로 한 줄 요약 →
