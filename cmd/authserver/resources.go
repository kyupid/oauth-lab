package main

// RFC 8707 Resource Indicators — "이 토큰을 어디에 쓸 것인가" 를 요청에 명시하게 한다.
//
// 1부에서는 AS 가 aud 를 :9001 로 고정 발급했다. 리소스서버가 여럿이면 그럴 수 없다.
// 클라이언트가 resource 파라미터로 대상을 지정하고, AS 는 그 값을 aud 에 박는다.
// 아무 값이나 받으면 안 되므로, AS 가 아는 리소스 목록 안에서만 허용한다.

// knownResources: AS 가 토큰을 발급해 줄 수 있는 리소스서버들.
var knownResources = map[string]string{
	"http://127.0.0.1:9001": "노트 API",
	"http://127.0.0.1:9004": "빌링 API",
}

func isKnownResource(r string) bool {
	_, ok := knownResources[r]
	return ok
}
