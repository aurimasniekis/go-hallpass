//go:build embedui

package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var dist embed.FS

// Dist returns the built UI (web/dist), embedded with the embedui build tag (HP-UI-016).
func Dist() (fs.FS, bool) {
	sub, err := fs.Sub(dist, "dist")
	return sub, err == nil
}
