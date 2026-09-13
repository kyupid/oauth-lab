# 스텝 12 — Revocation: 클라이언트가 토큰을 버린다

스텝 7 에서 refresh 재사용이 감지되면 AS 가 알아서 폐기했다. 그건 **서버의 방어**다.
revocation(RFC 7009)은 반대로 **클라이언트가 요청**하는 것이다. 로그아웃할 때, 토큰이 더 필요 없을 때.

## 폐기

```bash
# refresh 로 갱신이 되던 상태에서
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:9000/oauth2/revoke -d token=$RT
# 200

# 폐기 후 그 refresh 로 갱신 시도
curl -s -X POST http://127.0.0.1:9000/token -d grant_type=refresh_token -d refresh_token=$RT -d client_id=$CID
# invalid_grant — 알 수 없는 refresh token
```

refresh 를 폐기하면 그 Family 전체를 함께 지운다. refresh 를 revoke 하는 것은
"이 세션에서 파생될 수 있는 모든 것을 끊는다"는 뜻이기 때문이다.

## 두 가지 주의

**모르는 토큰에도 200 을 준다.** RFC 7009 의 요구다.

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:9000/oauth2/revoke -d token=아무거나
# 200
```

에러를 주면 공격자가 revoke 응답으로 "이 토큰이 존재하는지"를 알아낼 수 있다. 존재 여부를
숨기려고 언제나 200 을 준다.

**JWT access token 은 revoke 해도 만료까지 산다.** 스텝 6 에서 봤듯 리소스서버는 JWT 를
로컬 검증하므로 AS 에 묻지 않는다. 그래서 access token 을 revoke 해도 리소스서버는 만료(60초)
전까지 계속 통과시킨다.

그래서 revocation 의 실질 효과는 주로 **refresh token** 에 있다. refresh 를 죽이면 새 access 를
받지 못하니, 길어야 60초 뒤 세션이 실제로 끝난다. 즉시 끊어야 한다면 JWT 로컬 검증을 포기하고
introspection 으로 돌아가야 하는데, 그건 스텝 6~7 에서 본 트레이드오프 그대로다.

## 로그아웃의 완성

앱의 로그아웃은 두 가지를 함께 해야 한다.

1. 앱 세션 쿠키(sid) 삭제 — 앱↔사용자 관계를 끊는다 (1부에서 하던 것)
2. refresh token revoke — 앱↔AS 관계를 끊는다 (이번 스텝)

1 만 하면 앱에서는 로그아웃돼 보이지만, 유출된 refresh 는 여전히 살아 새 토큰을 찍어낼 수 있다.

## 코드에서 볼 곳

| 무엇 | 어디 |
|---|---|
| revocation 핸들러 | `cmd/authserver/revoke.go` |
| Family 함께 폐기 | `internal/store/store.go` `DeleteRefresh` → `RevokeFamily` |
| discovery 의 revocation_endpoint | `cmd/authserver/legacy.go` |

## 내가 채울 칸

- access token 을 revoke 해도 리소스서버가 잠깐 통과시키는 이유는? (스텝 6 로컬 검증과 연결) →
- 모르는 토큰에 왜 에러 대신 200 을 주나? →
- 로그아웃에서 refresh revoke 를 빠뜨리면 무엇이 남는가? →
