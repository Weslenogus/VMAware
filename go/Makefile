.PHONY: build vet fmt test cli windows darwin wasip1 wasm-browser all-targets clean

build:
	go build ./...

vet:
	go build ./... && go vet ./...

fmt:
	gofmt -l .

test:
	go test ./...

cli:
	go build -o bin/vmaware ./cmd/vmaware

windows:
	GOOS=windows GOARCH=amd64 go build -o bin/vmaware-windows-amd64.exe ./cmd/vmaware

darwin:
	GOOS=darwin GOARCH=arm64 go build -o bin/vmaware-darwin-arm64 ./cmd/vmaware
	GOOS=darwin GOARCH=amd64 go build -o bin/vmaware-darwin-amd64 ./cmd/vmaware

wasip1:
	GOOS=wasip1 GOARCH=wasm go build -o bin/vmaware-wasip1.wasm ./cmd/vmaware

wasm-browser:
	GOOS=js GOARCH=wasm go build -o bin/vmaware-browser.wasm ./wasm/browser
	cp "$$(go env GOROOT)/lib/wasm/wasm_exec.js" bin/ 2>/dev/null || \
		cp "$$(go env GOROOT)/misc/wasm/wasm_exec.js" bin/ 2>/dev/null || true

all-targets: cli windows darwin wasip1 wasm-browser

clean:
	rm -rf bin
