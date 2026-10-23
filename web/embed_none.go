//go:build !embedui

package webui

import "io/fs"

// Dist reports that this binary was built without the UI (build with -tags embedui after `pnpm build`).
func Dist() (fs.FS, bool) { return nil, false }
