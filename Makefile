.PHONY: as rs app attacker build fmt vet

as:        ## 인가서버 :9000
	go run ./cmd/authserver
rs:        ## 리소스서버 :9001
	go run ./cmd/resource
app:       ## 클라이언트 앱 :9002
	go run ./cmd/client
attacker:  ## 공격자 사이트 :9003
	go run ./cmd/attacker

build:
	go build ./...
fmt:
	gofmt -l -w .
vet:
	go vet ./...
