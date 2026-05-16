.PHONY: build build_mac build_mac_amd64 build_mac_arm64 build_ico set_logo

build:
	@echo Building windows binary...
	set GOOS=windows&& set GOARCH=amd64&& set CGO_ENABLED=0&& go build -trimpath -ldflags="-s -w" .
	@echo Done!

build_mac: build_mac_amd64 build_mac_arm64
	@echo Done!

build_mac_amd64: export GOOS=darwin
build_mac_amd64: export GOARCH=amd64
build_mac_amd64: export CGO_ENABLED=0
build_mac_amd64:
	@echo Building macOS amd64 binary...
	go build -trimpath -ldflags="-s -w" -o firefly-go-proxy-darwin-amd64 .

build_mac_arm64: export GOOS=darwin
build_mac_arm64: export GOARCH=arm64
build_mac_arm64: export CGO_ENABLED=0
build_mac_arm64:
	@echo Building macOS arm64 binary...
	go build -trimpath -ldflags="-s -w" -o firefly-go-proxy-darwin-arm64 .

build_ico:
	@echo Building application icon...
	magick logo.jpg -define icon:auto-resize=256,128,64,48,32,16 ./logo.ico
	@echo Done!

set_logo:
	@echo Embedding application icon...
	go-winres simply --icon ./logo.ico
	@echo Done!
