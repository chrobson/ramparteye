// Package builtin embeds the built-in detection signatures (*.yaml).
package builtin

import "embed"

// FS holds the built-in signature files.
//
//go:embed *.yaml
var FS embed.FS
