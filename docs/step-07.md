# 스텝 7 — Refresh token: 회전과 재사용 감지

## 문제: JWT 는 즉시 회수가 안 된다 (스텝 6 숙제)

access token 을 JWT 로 만들면 RS 가 로컬 검증해서 빠르다. 대신 **만료 전에는 못 막는다** —
로그아웃해도, 계정을 정지시켜도, 서명이 유효하니 exp 까지 통과한다.

**해법: access token 을 아주 짧게(여기선 60초) 두고, refresh token 으로 갱신한다.**
- access 가 짧으니 탈취돼도 60초 뒤 무용지물
- refresh 는 길지만(24h) opaque + AS 가 상태를 쥐고 있어서 **즉시 폐기 가능**

## 최초 로그인이 이제 둘을 준다

```json
{"access_token":"eyJ...(60초)", "refresh_token":"eoU4...(24h)", "expires_in":60}
```

갱신:
```bash
curl -s -X POST http://127.0.0.1:9000/token \
  -d grant_type=refresh_token -d refresh_token=$RT \
  -d client_id=demo-app -d client_secret=demo-secret | jq
```

## 회전 (rotation) — `./lab on rotation`

refresh 를 쓸 때마다 **새 refresh 를 발급하고 이전 것을 무효화**한다.

```
RT1 로 갱신 → 새 RT2 발급, RT1 무효
```

왜? refresh 는 수명이 길어 탈취 가치가 크다. 회전하면 "한 번 쓰면 폐기"라 탈취범과 진짜
사용자가 같은 refresh 를 오래 공유할 수 없다.

## 재사용 감지 — 회전의 진짜 목적

회전만으로는 "탈취됐다"를 모른다. 핵심은 **이미 쓴(회전된) refresh 가 또 오면**이다:

```
① RT1 로 갱신 → RT2 (정상)
② 이미 쓴 RT1 을 또 씀  → 🚨 invalid_grant "재사용 감지 — Family 전체 폐기"
③ 방금 정상이던 RT2 도  → "알 수 없는 refresh token" (같이 죽었다)
```

**②가 왜 탈취 신호인가:** 정상 클라이언트는 RT1 을 쓴 뒤 RT2 로 넘어간다. RT1 이 다시 온다는 건
= 누군가(공격자 또는 원래 사용자) **오래된 걸 들고 있다** = 복제됐다는 뜻.

**③ 왜 멀쩡한 RT2 까지 죽이나:** 지금 RT1 을 쓰는 게 공격자인지 사용자인지 알 수 없다.
그러니 **Family 전체를 폐기**하고 둘 다 다시 로그인하게 만든다. 조금 불편해도 그게 안전하다.
이것이 2.1 이 공개 클라이언트에 요구하는 "rotation 또는 sender-constrained" 중 rotation.

## 방어 OFF 와 비교 — `./lab off rotation`

```
같은 RT 3번 연속 → 매번 성공, refresh 값 그대로
```
회전이 없으면 탈취된 refresh 가 만료(24h)까지 계속 먹힌다. 감지도 못 한다.

## Family 개념

하나의 로그인에서 파생된 refresh 들을 `Family` 로 묶는다. 회전하면 같은 Family 가 이어진다.
재사용이 감지되면 그 Family 만 폐기한다 — 다른 기기의 다른 로그인(다른 Family)은 안 건드린다.

## 코드에서 볼 곳

| 무엇 | 어디 |
|---|---|
| refresh 발급 / 회전 / 재사용 감지 | `cmd/authserver/refresh.go` `grantRefreshToken` |
| Family 폐기 | `internal/store/store.go` `RevokeFamily` |
| access 수명 60초 | `cmd/authserver/jwt.go` `accessTokenJWT` (exp) |

## 내가 채울 칸

- access token 을 60초로 짧게 두면, JWT 의 "즉시 회수 불가" 문제가 왜 완화되나? →
- 재사용 감지에서 "두 번째 요청만" 막고 Family 는 살려두면 뭐가 뚫리나? →
- 회전을 껐을 때(=긴 수명 refresh 재사용) 탈취되면 피해가 얼마나 오래가나? →
