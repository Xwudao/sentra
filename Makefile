.PHONY: all web go-build test race bench tidy clean run

# Build the SPA and embed it, then build all Go packages.
all: web go-build

web:
	cd web && pnpm install --frozen-lockfile || pnpm install
	cd web && pnpm build
	rm -rf internal/webassets/dist
	mkdir -p internal/webassets/dist
	cp -R web/dist/. internal/webassets/dist/

go-build:
	go build ./...

test:
	go test ./...

race:
	go test -race ./...

bench:
	go test -run '^$$' -bench . -benchmem ./internal/engine/

tidy:
	go mod tidy
	cd web && pnpm install

# Build a Caddy binary with the module using the local working copy.
caddy:
	xcaddy build --with github.com/Xwudao/sentra=$(CURDIR)

clean:
	rm -rf web/dist web/node_modules
