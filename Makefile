all: deps format
	@mkdir -p bin/
	@bash --norc -i ./scripts/build.sh

deps:
	@go get github.com/golang/lint/golint

format:
	@gofmt -w .
	@golint ./...

test:
	@go test ./...

clean:
	@rm -rf bin

.PHONY: all deps test format
