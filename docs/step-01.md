# 스텝 1 — 가장 단순한(그리고 취약한) Authorization Code 플로우

## 띄우기

터미널 두 개:

```bash
make as    # :9000 인가서버
make app   # :9002 클라이언트 앱
```

브라우저로 <http://127.0.0.1:9002> → "인가서버로 로그인" → 사용자 이름 `alice` → "허용".

## A0. 먼저 볼 것: 6번의 HTTP 홉 중 사용자가 보는 건 2개뿐

이 랩은 **스텝 모드가 기본 켜짐**이다. 원래는 눈 깜짝할 새 지나가는 홉마다 화면이 멈추고,
지금 이게 어떤 종류의 홉인지 배지로 알려준다.

| 홉 | 누가 → 누구 | 사용자 눈에는 |
|---|---|---|
| ① | 앱 → 브라우저 `302` | 🔵 **안 보임** — 주소창이 한 번 바뀔 뿐 |
| ② | 브라우저 → 인가서버 `GET /authorize` | 🟢 **동의 화면** (인가서버 도메인!) |
| ③ | 사용자 → 인가서버 `POST /approve` | 🟢 "허용" 클릭 |
| ③.5 | 인가서버 → 브라우저 `302` | 🔵 **안 보임** — code 가 URL 에 실려 나간다 |
| ④ | 브라우저 → 앱 `GET /callback?code=…` | 🔵 **안 보임** — 브라우저의 역할은 여기서 끝 |
| ⑤ | **앱 서버 → 인가서버** `POST /token` | ⚫ **절대 안 보임** — 브라우저 밖의 대화 |
| ⑥ | 브라우저 → 앱 `GET /` | 🟢 결과 화면 |

즉 **🟢 사용자가 보는 화면은 딱 2개** (동의 화면, 결과 화면)이고, 나머지는 전부 자동이다.
그리고 access token 이 등장하는 ⑤번은 **브라우저가 존재조차 모르는 홉**이다.

다 익숙해지면 홈에서 **"스텝 모드 끄기"**를 눌러 실제 속도로 한 번 돌려보자.
서버 로그(`make as` / `make app` 터미널)에는 똑같이 홉이 다 찍히지만, 화면은 두 번만 바뀐다.
그게 진짜 사용자 경험이다.

## A. 브라우저로 한 번 완주하고, **주소창을 본다**

관찰할 것 세 가지:

1. `/authorize` 로 갈 때 URL 에 `client_id`, `redirect_uri`, `scope`, `response_type` 이 전부 평문으로 보인다
2. 돌아올 때 URL 이 `…/callback?code=XXXX` 다 — **인가코드가 브라우저 히스토리에 남는다**
3. 그런데 `access_token` 은 URL 어디에도 없다 → 앱 서버가 뒤에서 조용히 바꿔왔다 (`make app` 터미널 로그 확인)

## B. 같은 플로우를 curl 로 손수 (서버 로그를 보면서)

```bash
# ① 동의 화면 — 브라우저가 하는 일
curl -s "http://127.0.0.1:9000/authorize?response_type=code&client_id=demo-app&redirect_uri=http://127.0.0.1:9002/callback&scope=profile+notes:read" | grep -i hidden

# ② "허용" 버튼 — 302 Location 에서 code 를 꺼낸다
LOC=$(curl -s -o /dev/null -D - -X POST http://127.0.0.1:9000/approve \
  -d username=alice -d client_id=demo-app \
  -d 'redirect_uri=http://127.0.0.1:9002/callback' \
  -d 'scope=profile notes:read' | grep -i '^location:' | tr -d '\r')
CODE=$(echo "$LOC" | sed -n 's/.*code=\([^&]*\).*/\1/p'); echo "CODE=$CODE"

# ③ 토큰 교환 — 여기가 back channel
curl -s -X POST http://127.0.0.1:9000/token \
  -d grant_type=authorization_code -d code=$CODE \
  -d client_id=demo-app -d client_secret=demo-secret | jq
```

기대 결과:

```json
{
  "access_token": "cfM7b7Fpu0XuAE1pQgAXfej_4QXXmOv9khY-lfMKCi0",
  "expires_in": 599,
  "scope": "profile notes:read",
  "token_type": "Bearer"
}
```

## C. 지금 무엇이 깨져 있는지 직접 확인 (이게 스텝 3~5의 재료다)

**① 인가코드가 1회용이 아니다**

```bash
# ③ 을 똑같이 한 번 더 실행해 본다
```
→ 에러가 아니라 **새 access token 이 또 나온다.** code 가 한 번 새면 공격자는 몇 번이고 토큰을 찍어낼 수 있다. → 스텝 4

**② 등록하지 않은 redirect_uri 가 통과한다**

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
  "http://127.0.0.1:9000/authorize?response_type=code&client_id=demo-app&redirect_uri=http://127.0.0.1:9002/callback.evil&scope=profile"
```
→ `200`. 등록값은 `/callback` 인데 `/callback.evil` 도 받아준다 (prefix 매칭). → 스텝 4

**③ `state` 가 아예 없다**

`make app` 로그의 리다이렉트 URL 에 `state=` 가 없다. 클라이언트는 "내가 시작한 로그인이 맞는지"를 확인할 방법이 없다. → 스텝 3

**④ PKCE 가 없다**

`public-app` 은 `client_secret` 이 빈 클라이언트다. code 만 있으면 누구든 토큰으로 바꾼다:

```bash
# public-app 으로 code 를 받은 뒤, secret 없이 그대로 교환된다
```
→ 스텝 5

## 코드에서 볼 곳

| 무엇 | 어디 |
|---|---|
| front channel 진입점 | `cmd/authserver/main.go` `handleAuthorize` |
| 인가코드 발급 | `cmd/authserver/main.go` `handleApprove` |
| back channel 교환 | `cmd/authserver/main.go` `grantAuthorizationCode` |
| 의도적 취약점 4개 | `[VULN-1]` ~ `[VULN-4]` 주석으로 검색 |
| 홉을 멈춰 세우는 화면 | `internal/lab/ui.go` `RenderHop` |
| 에러를 리다이렉트할지 말지 | `cmd/authserver/http.go` `httpError` vs `redirectError` |

> `httpError` / `redirectError` 를 나눠둔 이유를 읽어볼 것. `client_id` 나 `redirect_uri` 자체가 의심스러울 때
> 리다이렉트해버리면 인가서버가 공격자의 open redirect 도구가 된다.

## 내가 채울 칸

- code 가 URL 에 남아도 (아직은) 큰 문제가 아닌 이유는? 무엇이 더 있어야 code 가 토큰이 되나? →
- `expires_in: 599` 는 무엇의 수명인가? 인가코드의 수명은 지금 몇 초인가? →
- 위 C-① 을 실행했을 때 두 번째로 나온 토큰도 실제로 동작할까? (스텝 2에서 확인) →
