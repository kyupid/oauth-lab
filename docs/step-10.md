# 스텝 10 — 리소스가 여럿일 때: PRM + Resource Indicators

> 여기부터 2부다. 1부(스텝 0~9)는 리소스서버가 하나였다. 실제로는 여럿이고,
> 그때 "이 토큰이 어느 서버 것인가"와 "클라이언트가 어느 인가서버로 가야 하는가"가 문제가 된다.

1부에서 `aud`를 :9001 로 고정 발급했다. 이제 리소스서버가 둘이다 — 노트(:9001)와 빌링(:9004).

```bash
./lab up   # rs(:9001 노트), rs2(:9004 빌링) 가 함께 뜬다
```

## A. Resource Indicators (RFC 8707) — 어느 리소스용 토큰인가

클라이언트가 `resource` 파라미터로 토큰의 대상을 지정한다. AS 는 그 값을 `aud` 에 박는다.

```bash
V=$(cat /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | head -c 64)
C=$(printf %s "$V" | openssl dgst -binary -sha256 | openssl base64 | tr '+/' '-_' | tr -d '=')

# 빌링(:9004) 대상 토큰을 요청한다
CODE=$(curl -s -o /dev/null -D - -X POST http://127.0.0.1:9000/approve \
  -d username=alice -d client_id=demo-app -d 'redirect_uri=http://127.0.0.1:9002/callback' \
  -d 'scope=profile billing:read' -d "code_challenge=$C" -d 'code_challenge_method=S256' \
  -d 'resource=http://127.0.0.1:9004' \
  | grep -i '^location:' | tr -d '\r' | sed -n 's/.*code=\([^&]*\).*/\1/p')
TOK=$(curl -s -X POST http://127.0.0.1:9000/token -d grant_type=authorization_code -d code=$CODE \
  -d client_id=demo-app -d client_secret=demo-secret -d "code_verifier=$V" \
  -d 'resource=http://127.0.0.1:9004' | jq -r .access_token)
```

이 토큰의 aud 는 :9004 다. 두 서버에 각각 들이밀어 본다.

```
빌링(:9004)로 /data  → 200
노트(:9001)로 /data  → 401   ← aud 불일치. 이 토큰은 빌링 것이다
```

빌링 서버가 침해돼 이 토큰이 새더라도, 노트 서버는 열지 못한다. **토큰 하나의 폭발 반경이 한 서버로 제한된다.** 1부 스텝 6의 aud 공격을, 이번엔 정식 문법으로 원천 차단하는 것이다.

AS 가 아무 대상이나 받아주면 안 된다. 등록된 리소스 목록 밖이면 거부한다.

```bash
# 모르는 resource → 거부
curl -s -o /dev/null -w "%{http_code}\n" \
  "http://127.0.0.1:9000/authorize?...&resource=http://evil.example"   # 302 (에러 리다이렉트)
```

그리고 authorize 때 지정한 대상과 token 때 지정한 대상이 달라도 거부한다. 중간에 대상을 바꿔치기할 수 없다.

```
authorize: resource=:9004,  token: resource=:9001  → invalid_target
```

## B. PRM (RFC 9728) — 클라이언트가 AS 를 어떻게 찾나

1부에서 클라이언트는 AS 주소를 코드에 하드코딩했다. 리소스서버가 여럿이고 각자 다른 AS 를 믿을 수 있으면, 클라이언트는 **리소스서버에게 물어봐서** AS 를 알아내야 한다.

리소스서버가 자기를 소개하는 문서가 PRM 이다.

```bash
curl -s http://127.0.0.1:9004/.well-known/oauth-protected-resource | jq
```
```json
{
  "resource": "http://127.0.0.1:9004",
  "authorization_servers": ["http://127.0.0.1:9000"],
  "scopes_supported": ["profile", "billing:read"],
  "resource_name": "빌링"
}
```

발견 흐름은 이렇다.

1. 클라이언트가 토큰 없이 리소스서버를 찔러본다 → `401`
2. `401` 의 `WWW-Authenticate` 헤더가 PRM 위치를 알려준다

```bash
curl -si http://127.0.0.1:9004/data | grep -i www-authenticate
# Bearer error="...", resource_metadata="http://127.0.0.1:9004/.well-known/oauth-protected-resource"
```

3. 클라이언트가 PRM 을 읽어 `authorization_servers` 를 얻는다
4. 그 AS 의 `/.well-known/openid-configuration`(스텝 8)을 읽어 authorize·token 주소를 얻는다
5. 이제 로그인 플로우를 시작한다

**클라이언트는 리소스서버 주소 하나만 알면 된다.** AS 주소도, 엔드포인트 경로도 전부 문서를 따라가며 알아낸다. Claude Code 같은 MCP 클라이언트가 처음 보는 서버에 붙을 수 있는 게 이 발견 체인 덕분이다.

## 왜 이게 MCP 설계에 필요한가

MCP 클라이언트(Claude Code, Codex)는 사전에 서버를 모른다. 사용자가 리소스서버 URL 하나를 주면, 클라이언트가 PRM → discovery 를 따라 AS 를 찾고 로그인한다.

그리고 리소스가 여럿이면 각각 다른 aud 의 토큰이 필요하다 — Resource Indicators 가 그걸 표현한다. 이 둘이 "리소스가 여럿인 세계"의 최소 문법이다.

## 코드에서 볼 곳

| 무엇 | 어디 |
|---|---|
| 등록된 리소스 목록 | `cmd/authserver/resources.go` |
| resource 검증 (authorize/token) | `cmd/authserver/main.go` `handleAuthorize` / `grantAuthorizationCode` |
| PRM 문서 | `cmd/resource/main.go` `handlePRM` |
| 401 이 PRM 위치를 알려줌 | `cmd/resource/main.go` `unauthorized` |
| aud 를 자기 식별자와 대조 | `cmd/resource/jwt.go` |
| 두 번째 리소스서버 (환경변수) | `RS_PORT=9004 RS_NAME=빌링 ...` (lab 스크립트) |

## 내가 채울 칸

- resource 를 지정하지 않으면 어느 aud 로 발급되나? (`grantAuthorizationCode` 확인) →
- PRM 의 `authorization_servers` 가 여러 개면 클라이언트는 어느 것을 고르나? →
- Resource Indicators 없이 "모든 리소스에 통하는 토큰" 하나만 쓰면 무엇이 위험한가? (스텝 6 aud 공격과 연결) →
