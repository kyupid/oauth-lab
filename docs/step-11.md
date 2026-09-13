# 스텝 11 — DCR: 클라이언트가 스스로 등록한다

1부의 클라이언트(demo-app, public-app)는 AS 코드에 하드코딩돼 있었다. `client_id` 를 미리 심어둔 것이다.

Claude Code 같은 외부 클라이언트는 그럴 수 없다. 사용자가 자기 노트북에서 처음 실행하는 순간
`client_id` 가 없다. 그래서 **스스로 등록해서** `client_id` 를 발급받는다. 이것이 DCR(RFC 7591)이다.

## 등록

DCR 은 SaaS 프로파일에서만 연다. 온프렘은 설치 시 provisioning 하므로 필요 없다.

```bash
# 기본은 꺼져 있다
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:9000/connect/register \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"Claude Code","redirect_uris":["http://127.0.0.1:53211/callback"]}'
# 403

./lab enable dcr
curl -s -X POST http://127.0.0.1:9000/connect/register \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"Claude Code","redirect_uris":["http://127.0.0.1:53211/callback"]}' | jq
```
```json
{
  "client_id": "dcr-vFNyH1my4Go",
  "client_name": "Claude Code",
  "redirect_uris": ["http://127.0.0.1:53211/callback"],
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"]
}
```

`redirect_uris` 의 `127.0.0.1:53211` 을 눈여겨보라. 네이티브 클라이언트는 자기 기기에서
임의 포트로 콜백을 받는다(loopback). 그래서 redirect_uri 를 미리 등록해 둘 수 없고,
등록 시점에 클라이언트가 알려주는 것이다.

발급된 `client_id` 로 곧바로 로그인 플로우를 시작할 수 있다. secret 이 없는 공개 클라이언트이므로
PKCE 가 필수다(스텝 5). 그래서 DCR 로 등록한 클라이언트도 code 가로채기로부터 안전하다.

## 누가 등록할 수 있는가

`redirect_uris` 만 주면 누구나 클라이언트를 만들 수 있다는 점이 걸린다. 실제 서비스는 여기에
정책을 둔다 — 초기 액세스 토큰(software statement), redirect_uri 스킴·호스트 제약, 심사.

이 랩은 그 자리(정책 지점)만 주석으로 표시해 뒀다. `handleRegister` 의 `[정책 지점]` 을 보라.
외부 클라이언트는 보통 loopback(127.0.0.1:랜덤포트)이나 커스텀 스킴만 허용한다.

## 신뢰 등급에 따른 분기

설계 문서(D9)는 클라이언트를 둘로 나눈다.

| | 1st-party (Operant) | external (Claude Code) |
|---|---|---|
| 등록 | 설치 시 provisioning | DCR |
| 동의 화면 | 생략 | 필수 |
| scope | 등록 시 고정, 전권 | 제한적, 사용자에 노출 |

관리자가 직접 설치한 앱에 "이 앱을 신뢰하시겠습니까?"는 무의미하다. 반면 DCR 로 등록한
제3자 클라이언트는 폭발 반경이 실재하므로 동의와 제한적 scope 가 의미를 갖는다.

## 코드에서 볼 곳

| 무엇 | 어디 |
|---|---|
| 등록 핸들러 | `cmd/authserver/dcr.go` `handleRegister` |
| discovery 의 registration_endpoint | `cmd/authserver/legacy.go` `handleDiscovery` |
| 토글 | `./lab enable dcr` / `./lab disable dcr` |

## 내가 채울 칸

- DCR 로 등록한 클라이언트가 공개 클라이언트(secret 없음)인 이유는? 그래서 무엇이 필수가 되나 →
- `redirect_uris` 검증을 안 하면 어떤 공격이 가능한가? (스텝 4 redirect_uri 와 연결) →
- 1st-party 앱과 external 앱을 왜 다르게 다루나? 동의 화면을 external 에만 두는 근거는? →
