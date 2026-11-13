package extract

import (
	"io/fs"
	"path"
	"sync"
	"time"

	"github.com/google/osv-scalibr/extractor/filesystem"
)

// Siblings are files the edge readers and the unpinned check read beside a lockfile.
var Siblings = map[string]bool{
	"Gemfile": true, "gems.rb": true, "package.json": true, "composer.json": true,
	"pyproject.toml": true, "Cargo.toml": true, "Pipfile": true,
}

var (
	wantOnce sync.Once
	wantExts []filesystem.Extractor
)

type nameInfo struct {
	name string
	size int64
}

func (n nameInfo) Name() string       { return n.name }
func (n nameInfo) Size() int64        { return n.size }
func (n nameInfo) Mode() fs.FileMode  { return 0o644 }
func (n nameInfo) ModTime() time.Time { return time.Time{} }
func (n nameInfo) IsDir() bool        { return false }
func (n nameInfo) Sys() any           { return nil }

// Wants reports whether a dependency reader, an edge reader or the unpinned and unsupported checks
// would read the file at this path. Used to decide which files to fetch from a repository, so the
// GitHub route reads exactly what the CLI route reads.
func Wants(p string, size int64) bool {
	base := path.Base(p)
	if Siblings[base] || unsupportedFiles[base] != "" {
		return true
	}
	if _, ok := manifestRules[base]; ok {
		return true
	}
	wantOnce.Do(func() { wantExts, _ = sourceExtractors() })
	api := fileAPI{path: p, info: nameInfo{name: base, size: size}}
	for _, e := range wantExts {
		if e.FileRequired(api) {
			return true
		}
	}
	return false
}
