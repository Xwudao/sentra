.PHONY: all web go-build test race bench tidy clean run web-dev

# Local development defaults for `make run`.
DEV_DB ?= .dev/sentra.db
DEV_WAF_ADDR ?= 127.0.0.1:8080
DEV_ADMIN_ADDR ?= 127.0.0.1:2020

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

# Run the standalone Go backend for local development. Pair it with
# `make web-dev`: the Vite dev server proxies /api and /metrics to it
# (see web/vite.config.ts) so the SPA hot-reloads against the live API.
run:
	mkdir -p $(dir $(DEV_DB))
	go run ./cmd/sentra \
		-db $(DEV_DB) \
		-listen $(DEV_WAF_ADDR) \
		-admin $(DEV_ADMIN_ADDR)

# Start the Vite dev server for the web UI (proxies to `make run`).
web-dev:
	cd web && pnpm dev

tidy:
	go mod tidy
	cd web && pnpm install

# Build a Caddy binary with the module using the local working copy.
caddy:
	xcaddy build --with github.com/Xwudao/sentra=$(CURDIR)

clean:
	rm -rf web/dist web/node_modules
