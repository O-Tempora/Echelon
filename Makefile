.PHONY: build
build: 
	go build -o app cmd/server/*.go

.PHONY: run
run: build
	./app

.PHONY: gen
gen: 
	mkdir -p internal
	protoc --go_out=internal --go_opt=paths=source_relative \
			--go-grpc_out=internal --go-grpc_opt=paths=source_relative \
			api/netvuln_v1/service.proto

.PHONY: rmlog
rmlog:
	rm logs/logs.log

.PHONY: lint
lint: 
	go fmt ./... && \
	go vet -json ./...

.PHONY: test
test:
	go clean -testcache
	go test -v cmd/server/*.go

.DEFAULT_GOAL=lint