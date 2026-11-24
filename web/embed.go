// Package webassets embeds the HTML templates and static files so the
// ramparteye binary is self-contained.
package webassets

import (
	"embed"
	"io/fs"
)

//go:embed all:templates static
var embedded embed.FS

// Templates is rooted at web/templates (layout.html, components/, pages).
var Templates fs.FS = mustSub("templates")

// Static is rooted at web/static (app.css, app.js, htmx).
var Static fs.FS = mustSub("static")

func mustSub(dir string) fs.FS {
	f, err := fs.Sub(embedded, dir)
	if err != nil {
		panic(err)
	}
	return f
}
