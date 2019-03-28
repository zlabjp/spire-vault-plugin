out_dir := out/bin

utils = github.com/goreleaser/goreleaser \
		github.com/golang/dep/cmd/dep

uname := $(shell uname -s)
ifeq (${uname},Linux)
	OS=linux
endif
ifeq (${uname},Darwin)
	OS=darwin
endif

build-linux: OS=linux
build-linux: build

build-darwin: OS=darwin
build-darwin: build

build: clean
	cd cmd/server/vault-upstream-ca && GOOS=$(OS) GOARCH=amd64 go build -o ../../../$(out_dir)/server/vault_upstream_ca  -i

utils: $(utils)

$(utils): noop
	go get $@

vendor: Gopkg.lock Gopkg.toml
	dep ensure

revendor:
	rm Gopkg.lock Gopkg.toml
	rm -rf vendor
	dep init

test:
	go test -race ./cmd/... ./pkg/...

release:
	goreleaser || true

clean:
	go clean ./cmd/... ./pkg/...
	rm -rf out

noop:

.PHONY: all build vendor utils test clean
