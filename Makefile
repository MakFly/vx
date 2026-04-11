.PHONY: all build build-linux test lint vet clean scan-test

all: build test lint

build:
	go build -o vx ./main.go

build-linux:
	GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o vx-linux-amd64 ./main.go

test:
	go test ./... -v -race

lint:
	golangci-lint run ./...

vet:
	go vet ./...

clean:
	rm -f vx vx-linux-amd64

scan-test:
	./vx scan https://www.iautos.fr
