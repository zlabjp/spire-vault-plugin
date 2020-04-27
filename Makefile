out_dir := out/bin

uname := $(shell uname -s)
ifeq (${uname},Linux)
	OS=linux
endif
ifeq (${uname},Darwin)
	OS=darwin
endif

export GO111MODULE=on
export GOPROXY=https://proxy.golang.org

build-linux: OS=linux
build-linux: build

build-darwin: OS=darwin
build-darwin: build

build: clean
	cd cmd/server/vault-upstream-ca && GOOS=$(OS) GOARCH=amd64 go build -o ../../../$(out_dir)/server/vault_upstream_ca  -i
	cd cmd/server/vault-upstream-authority && GOOS=$(OS) GOARCH=amd64 go build -o ../../../$(out_dir)/server/vault_upstream_authority  -i

test:
	go test -race ./cmd/... ./pkg/...

clean:
	go clean ./cmd/... ./pkg/...
	rm -rf out

noop:

.PHONY: all build  test clean
