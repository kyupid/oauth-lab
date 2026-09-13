# oauth-lab

OAuth 2.0 → 2.1, 그리고 OIDC를 **직접 구현하고, 취약점을 심고, 보완하며** 배우는 학습용 랩.
서버는 stdlib만 쓴다(외부 의존성 없음). Go 1.23+.

> ⚠️ 학습용 코드다. 일부러 취약하게 만든 부분이 있다(`[VULN-n]` 주석). 실제 서비스에 쓰지 말 것.
> 공격 실습은 오직 이 랩의 로컬 서버(:9000~:9004)만 대상으로 한다.

## 실행

```bash
./lab up      # 서버 전부 띄우기
./lab status  # 현황
./lab logs    # 로그 한 화면에 모아보기
./lab down    # 전부 끄기
```

| 포트 | 서버 |
|---|---|
| :9000 | 인가서버 (AS) |
| :9001 | 리소스서버 (노트) |
| :9004 | 리소스서버 (빌링) |
| :9002 | 앱 (클라이언트) |
| :9003 | 공격자 사이트 |

브라우저로 <http://127.0.0.1:9002> 접속. 앱 화면은 **스텝 모드**를 지원해 홉마다 멈추며,
어느 것이 사용자가 보는 화면이고 어느 것이 서버 간 통신인지 배지로 보여준다.

## 방어 토글

각 방어를 껐다 켜며 같은 공격을 방어 전후로 돌려볼 수 있다(재시작 불필요).

```bash
./lab off state       # 방어 끄기 → 공격이 성공한다
./lab on  state       # 다시 켜기
./lab enable dcr      # 기본 꺼진 기능 켜보기 (implicit · ropc · dcr)
```

방어: `state · redirect · onetime · pkce · jwt · aud · algnone · rotation`

## 커리큘럼

`docs/step-00.md` ~ `step-12.md` 를 순서대로 따라간다.

**1부 — 단일 클라이언트/리소스**

- **0~2** 역할과 채널, Authorization Code 플로우, 리소스서버와 scope
- **3~5** CSRF → state, redirect_uri 탈취 → 완전일치·1회용 code, code 가로채기 → PKCE
- **6~7** opaque → JWT·JWKS(alg:none/aud 공격), refresh 회전과 재사용 감지
- **8~9** 2.1 감사(implicit·ROPC 제거), OIDC(id_token·nonce·UserInfo)

**2부 — 리소스·클라이언트가 여럿인 세계 (MCP 문맥)**

- **10** PRM(RFC 9728)·Resource Indicators(RFC 8707) — 여러 리소스서버, 발견 체인
- **11** DCR(RFC 7591) — 클라이언트가 런타임에 스스로 등록
- **12** Revocation(RFC 7009) — 클라이언트가 토큰을 버린다, 로그아웃의 완성

각 스텝은 "취약하게 만들기 → 직접 공격 → 보완" 순서로 진행하며,
문서 끝의 "내가 채울 칸"을 직접 채우는 것이 학습의 핵심이다.
