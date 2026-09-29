// Package sentra is the root import that registers the Caddy HTTP handler.
// Building Caddy with `xcaddy build --with github.com/Xwudao/sentra` picks up
// this package, which blank-imports the adapter.
package sentra

import (
	_ "github.com/Xwudao/sentra/caddy"
)
