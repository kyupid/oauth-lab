package lab

import (
	"os"
	"strings"
)

// 방어 토글. 프로젝트 루트의 .lab-off 파일에 적힌 이름들이 "꺼진 방어" 다.
// 요청마다 파일을 다시 읽으므로 서버를 재시작할 필요가 없다 — 껐다 켜고 바로 브라우저에서 재시도하면 된다.
//
//	./lab off state   → state 검증 끔 (스텝 3 공격이 성공한다)
//	./lab on  state   → 다시 켬
const offFile = ".lab-off"

// Off 는 해당 방어가 꺼져 있으면 true 를 돌려준다.
func Off(name string) bool {
	b, err := os.ReadFile(offFile)
	if err != nil {
		return false // 파일이 없으면 모든 방어가 켜진 상태
	}
	for _, line := range strings.Fields(string(b)) {
		if line == name {
			return true
		}
	}
	return false
}

// OffList 는 지금 꺼져 있는 방어 목록이다 (상태 표시용).
func OffList() []string {
	b, err := os.ReadFile(offFile)
	if err != nil {
		return nil
	}
	return strings.Fields(string(b))
}

// On 은 "기본 꺼짐" 인 위험 기능이 켜져 있는지 본다 (.lab-on 파일).
// 방어(Off)와 방향이 반대다: 2.1 이 제거한 implicit/ropc 같은 것에 쓴다.
func On(name string) bool {
	b, err := os.ReadFile(".lab-on")
	if err != nil {
		return false
	}
	for _, line := range strings.Fields(string(b)) {
		if line == name {
			return true
		}
	}
	return false
}
