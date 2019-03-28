out_dir := out/bin

utils = github.com/goreleaser/goreleaser \
		github.com/golang/dep/cmd/dep

build: clean
	cd cmd/server/vault-upstream-ca && go build -o ../../../$(out_dir)/server/vault_upstream_ca  -i

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
