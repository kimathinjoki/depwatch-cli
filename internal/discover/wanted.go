package discover

import (
	"path"
	"strings"
)

// Listed is a file of a repository's listing, as a forge reports it.
type Listed struct {
	Path string
	Size int64
}

// Skipped reports whether a path lies in a folder the walk never enters, or one ignored.
func Skipped(p string, ignore []string) bool {
	dir := path.Dir(p)
	for _, seg := range strings.Split(dir, "/") {
		if SkippedDirs[seg] {
			return true
		}
	}
	for _, ig := range ignore {
		ig = strings.Trim(path.Clean(ig), "/")
		if ig != "" && (dir == ig || strings.HasPrefix(dir, ig+"/")) {
			return true
		}
	}
	return false
}
