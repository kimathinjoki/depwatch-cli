// Package discover walks a part and lists every file, skipping folders that are never part of it.
package discover

import (
	"io/fs"
	"path"
	"sort"
	"strings"
)

// SkippedDirs are never walked: version control, installed dependencies and tool caches.
// Installed dependencies are read through their lockfile, not their folders.
var SkippedDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true,
	"node_modules": true, "vendor": true, "bower_components": true,
	".venv": true, "venv": true, "__pycache__": true, ".tox": true,
	".dart_tool": true, ".bundle": true, ".gradle": true,
}

// File is one regular file inside the part.
type File struct {
	Path string // slash separated, relative to the root
	Info fs.FileInfo
}

// Walk lists every regular file under fsys, in path order, skipping SkippedDirs and the ignored
// folders (slash paths relative to the root, as written under ignore in depwatch.yml).
func Walk(fsys fs.FS, ignore []string) ([]File, error) {
	ignored := map[string]bool{}
	for _, ig := range ignore {
		ignored[strings.Trim(path.Clean(ig), "/")] = true
	}
	var out []File
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if p == "." {
				return err
			}
			// An unreadable folder is recorded by the caller through the returned file list being
			// incomplete; here it is reported as a file that could not be read.
			out = append(out, File{Path: p})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if p == "." {
				return nil
			}
			if SkippedDirs[d.Name()] || ignored[p] {
				return fs.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			out = append(out, File{Path: p})
			return nil
		}
		out = append(out, File{Path: p, Info: info})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, err
}
