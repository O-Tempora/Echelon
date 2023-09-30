.PHONY: build
build: 
	go build -o server cmd/server/main.go

.PHONY: run
run: build
	./server

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

.DEFAULT_GOAL=lint