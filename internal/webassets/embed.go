// Package webassets embeds the built React admin SPA. The dist directory is
// populated by the frontend build; a placeholder keeps `go build` working
// before the SPA is built.
package webassets

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var files embed.FS

// Dist returns the filesystem rooted at the SPA build output.
func Dist() fs.FS {
	sub, err := fs.Sub(files, "dist")
	if err != nil {
		panic(err)
	}
	return sub
}
