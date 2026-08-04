.PHONY: build check test

build:
	go build -trimpath -o ./bin/eventctl ./cmd/eventctl

test:
	go test ./...

check:
	./scripts/check.sh
