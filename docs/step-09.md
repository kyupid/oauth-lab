# 스텝 9 — OIDC: OAuth 위에 "인증(누구인가)" 얹기

OAuth 2.0 은 **위임된 인가**용이다. 앱은 access token 을 받아도 "누구인지" 모른다 —
토큰이 opaque 면 못 읽고, JWT 여도 그 aud 는 리소스서버지 앱이 아니다.
그래서 앱이 신원을 알려면 /me(UserInfo)를 호출해야 했다.

OIDC 는 그 빈칸을 **id_token** 으로 채운다.

## 두 토큰의 결정적 차이 (직접 발급해 비교)

`scope` 에 `openid` 를 넣으면 `/token` 이 id_token 도 준다:

```
id_token     : {"aud":"demo-app",              "sub":"alice", "nonce":"...", "auth_time":...}
access token  : {"aud":"http://127.0.0.1:9001", "sub":"alice", "scope":"..."}
```

| | id_token | access token |
|---|---|---|
| aud (수신자) | **앱 (demo-app)** | **리소스서버 (:9001)** |
| 누가 읽나 | 앱 | 리소스서버 |
| 목적 | **누구인가** (인증) | 무엇을 할 수 있나 (인가) |
| 특유 claim | nonce, auth_time | scope |

**핵심: aud 가 다르다.** id_token 은 앱 앞으로, access token 은 RS 앞으로 발급된다.
그래서 **access token 으로 로그인 처리하면 안 된다** — 그건 나(앱)를 수신자로 하지 않는다.

## 앱은 이제 /me 없이 사용자를 안다

로그인 후 홈:
```
로그인 완료. id_token 으로 확인한 사용자: alice — /me 호출 없이 앱이 바로 안다 (OIDC).
```

앱이 id_token 을 직접 열어 `sub` 를 읽는다. 검증 항목(`cmd/client/oidc.go`):
1. **서명** (AS 의 JWKS)
2. **iss** = 우리가 아는 AS
3. **aud** = 나(clientID) — 남의 앱용 id_token 거부
4. **nonce** = 내가 보낸 값 — replay 거부
5. **exp**

## nonce — id_token 판 state

앱이 `/authorize` 에 nonce 를 보내고 쿠키에 저장 → AS 가 id_token 에 그대로 넣어 돌려줌 →
앱이 대조. "이 id_token 이 방금 내가 시작한 로그인의 것" 임을 보장한다.
(state 가 콜백 CSRF 를 막듯, nonce 는 id_token replay 를 막는다.)

## UserInfo 엔드포인트

id_token 에 없는 추가 정보가 필요하면 access token 으로 물어본다:
```bash
curl -s -H "Authorization: Bearer $AT" http://127.0.0.1:9000/userinfo
# {"sub":"alice","name":"Alice"}
```

## "access token 으로 로그인" 이 왜 사고였나 (역사)

OIDC 표준화(2014) 전, 많은 앱이 소셜로그인에서 access token 만 받고 "로그인 성공" 처리했다.
문제:
- access token 은 aud 가 앱이 아니다 → **다른 앱용 토큰을 들고 와도 통과** (스텝 6 aud 공격과 같은 뿌리)
- "방금 인증했다" 는 보장이 없다 (auth_time/nonce 없음)

id_token 은 이 둘을 명시적으로 담아 **"이 사람은 alice, 너(앱)한테, 방금 인증했다"** 를 증명한다.

## 전체 그림 (스텝 0~9)

```
인증(누구)         OIDC / id_token       ← 스텝 9
   │
위임된 인가(무엇)   OAuth 2.0/2.1         ← 스텝 1~8
   │
방어 계층          state, PKCE, redirect_uri exact,
                   code 1회용, JWT 검증(alg/aud), refresh 회전
```

## 코드에서 볼 곳

| 무엇 | 어디 |
|---|---|
| id_token 서명 (aud=client, nonce, auth_time) | `cmd/authserver/oidc.go` `signIDToken` |
| openid scope 시 발급 | `cmd/authserver/main.go` `grantAuthorizationCode` |
| id_token 검증 (앱) | `cmd/client/oidc.go` `verifyIDToken` |
| UserInfo | `cmd/authserver/oidc.go` `handleUserInfo` |

## 내가 채울 칸

- access token 으로 로그인을 처리하면 안 되는 이유를 aud 로 한 문장 →
- nonce 와 state 는 각각 무엇의 replay/CSRF 를 막나? (두 토큰을 구분해서) →
- id_token 의 payload 도 base64 라 누구나 읽는다. 그런데 왜 "인증됐다" 를 믿을 수 있나? →
