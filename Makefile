.PHONY: build run test vet fmt demo

build:
	go build -o pkgrepo .

run:
	PKG_DELETION_COOLDOWN=$${PKG_DELETION_COOLDOWN:-24h} go run .

test:
	go test -count=1 ./...

vet:
	go vet ./...

fmt:
	gofmt -w *.go

demo:
	bash demo.sh
