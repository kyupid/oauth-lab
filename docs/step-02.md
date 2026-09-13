# 스텝 2 — 리소스서버와 scope

## 띄우기

터미널 세 개: `make as` / `make rs` / `make app`

브라우저로 <http://127.0.0.1:9002> 에서 로그인하면 홈에 `/me`, `/notes` 결과가 뜬다.

## 이 스텝의 한 줄

**리소스서버 코드에 "누구인가" 를 묻는 줄은 한 줄도 없다.** 토큰이 유효한지, 그리고
그 토큰이 이 엔드포인트에 필요한 scope 를 담고 있는지만 본다.

## 확인

```bash
# 토큰 하나 받아오는 헬퍼
tok() { C=$(curl -s -o /dev/null -D - -X POST http://127.0.0.1:9000/approve \
    -d username=$1 -d client_id=demo-app \
    -d 'redirect_uri=http://127.0.0.1:9002/callback' -d "scope=$2" \
  | grep -i '^location:' | tr -d '\r' | sed -n 's/.*code=\([^&]*\).*/\1/p')
  curl -s -X POST http://127.0.0.1:9000/token -d grant_type=authorization_code \
    -d code=$C -d client_id=demo-app -d client_secret=demo-secret | jq -r .access_token; }

FULL=$(tok alice "profile notes:read")
NARROW=$(tok alice "profile")
```

| 실험 | 결과 |
|---|---|
| `Bearer $FULL` 로 `/notes` | `200` — 메모가 나온다 |
| `Bearer $NARROW` 로 `/notes` | **`403 insufficient_scope`** |
| `Bearer 아무거나` 로 `/me` | **`401 invalid_token`** |
| `/me?access_token=$FULL` | **`400`** — OAuth 2.1 이 금지 |

### 401 과 403 을 왜 나누나

```
401 invalid_token      → 토큰이 못 쓴다. 다시 받아와야 한다
403 insufficient_scope → 토큰은 멀쩡한데 권한이 모자란다.
                         다시 로그인해도 소용없고, 더 넓은 scope 로 다시 받아야 한다
```

클라이언트가 이 둘을 구분해야 "재로그인" 과 "권한 추가 요청" 중 뭘 할지 정할 수 있다.
`WWW-Authenticate` 헤더에 그 이유가 실린다 (RFC 6750 §3).

## introspection: 리소스서버가 인가서버에 되묻는다

토큰이 opaque 랜덤 문자열이라 리소스서버 혼자서는 아무것도 알 수 없다. 그래서 매 요청마다 물어본다:

```bash
curl -s -u resource-server:rs-secret -X POST http://127.0.0.1:9000/introspect -d token=$FULL | jq
```
```json
{"active":true,"scope":"profile notes:read","sub":"alice","client_id":"demo-app","exp":1789182030}
```

두 가지를 눈여겨볼 것:

1. **이 엔드포인트는 보호돼 있다.** 자격증명 없이 부르면 `401`.
   아무나 부를 수 있으면 "이 토큰 살아있어?" 를 무한히 물어보는 신탁(oracle)이 된다.
2. **모르는 토큰에도 `404` 가 아니라 `{"active": false}` 로 답한다** (RFC 7662).
   "존재는 하는데 만료" 와 "아예 없음" 을 구분당하지 않기 위해서다.

대가는 **매 요청마다 왕복**이다. 인가서버가 죽으면 리소스서버도 멈춘다.
스텝 6에서 JWT 로 바꿔 이 왕복을 없앤다 (대신 즉시 회수를 잃는다).

## 스텝 1이 남긴 숙제의 답

> 같은 code 로 뽑은 **두 번째** 토큰도 실제로 동작할까?

```
1번째 토큰 → /notes  200
2번째 토큰 → /notes  200   ← 공격자가 code 를 훔쳤다면 이게 그의 토큰이다
```

**동작한다.** code 를 한 번 훔치면 공격자는 자기 토큰을 따로 발급받아
피해자의 메모를 그대로 읽는다. 피해자 쪽은 아무 일도 없었던 것처럼 보인다.
→ 스텝 4에서 인가코드를 1회용으로 만든다.

## 코드에서 볼 곳

| 무엇 | 어디 |
|---|---|
| scope 게이트 | `cmd/resource/main.go` `requireScope` |
| Bearer 파싱 (대소문자 무시) | `cmd/resource/main.go` `bearerToken` |
| scope 비교가 부분문자열이 아닌 이유 | `cmd/resource/main.go` `hasScope` |
| introspection 엔드포인트 | `cmd/authserver/main.go` `handleIntrospect` |

## 내가 채울 칸

- `hasScope` 를 `strings.Contains(granted, want)` 로 바꾸면 어떤 토큰이 뚫리나? →
- `/notes` 응답의 `owner` 는 어디서 왔나? 요청에 사용자 이름이 실려 있었나? →
- 인가서버를 끄고 `/me` 를 호출하면 몇 번이 나오고, 그게 왜 `401` 이 아니라 `502` 여야 하나? →
