// Package discover walks a part and lists every file, skipping folders that are never part of it.
package discover

import (
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
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
	// NotFollowed, when set, is why a symbolic link was not followed: it leads outside the part's
	// folder, or nowhere. Nothing was read through it. Dir says it leads to a folder.
	NotFollowed string
	Dir         bool
}

// Reasons a symbolic link is not followed.
const (
	LinkOutsideFile   = "a symbolic link to a file outside the project folder; not followed"
	LinkOutsideFolder = "a symbolic link to a folder outside the project folder; not followed (list it under ignore in depwatch.yml if it holds no dependencies)"
	LinkBroken        = "a symbolic link whose target does not exist"
)

// Walk lists every regular file under fsys, in path order, skipping SkippedDirs and the ignored
// folders (slash paths relative to the root, as written under ignore in depwatch.yml). Symbolic
// links are not followed.
func Walk(fsys fs.FS, ignore []string) ([]File, error) {
	return walk(fsys, "", ignore)
}

// WalkRoot walks fsys as Walk does, where fsys is the folder root on disk, and follows symbolic
// links. A link to a file that stays inside root is listed under the link's own path and read
// through it. A link to a folder inside root is not entered: its target is walked under its own
// path. A link leading outside root, or nowhere, is listed with NotFollowed set, so the caller can
// record it as not read rather than skip it in silence.
func WalkRoot(fsys fs.FS, root string, ignore []string) ([]File, error) {
	return walk(fsys, root, ignore)
}

func walk(fsys fs.FS, root string, ignore []string) ([]File, error) {
	ignored := map[string]bool{}
	for _, ig := range ignore {
		ignored[strings.Trim(path.Clean(ig), "/")] = true
	}
	realRoot := ""
	if root != "" {
		r, err := filepath.EvalSymlinks(root)
		if err != nil {
			return nil, err
		}
		realRoot = r
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
		if d.Type()&fs.ModeSymlink != 0 {
			if realRoot == "" || SkippedDirs[d.Name()] || ignored[p] {
				return nil
			}
			if f, ok := followLink(root, realRoot, p); ok {
				out = append(out, f)
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

// followLink decides what a symbolic link at p (relative to root) lists as.
func followLink(root, realRoot, p string) (File, bool) {
	name := path.Base(p)
	target, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(p)))
	if err != nil {
		return File{Path: p, Info: linkInfo{name: name}, NotFollowed: LinkBroken}, true
	}
	st, err := os.Stat(target)
	if err != nil {
		return File{Path: p, Info: linkInfo{name: name}, NotFollowed: LinkBroken}, true
	}
	rel, err := filepath.Rel(realRoot, target)
	inside := err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
	switch {
	case st.IsDir() && inside:
		return File{}, false // its target is walked under its own path
	case st.IsDir():
		return File{Path: p, NotFollowed: LinkOutsideFolder, Dir: true}, true
	case !st.Mode().IsRegular():
		return File{}, false
	case inside:
		return File{Path: p, Info: renamed{FileInfo: st, name: name}}, true
	default:
		return File{Path: p, Info: renamed{FileInfo: st, name: name}, NotFollowed: LinkOutsideFile}, true
	}
}

// renamed is a link target's file information under the link's own name.
type renamed struct {
	fs.FileInfo
	name string
}

func (r renamed) Name() string { return r.name }

// linkInfo describes a link with no target, by name only.
type linkInfo struct{ name string }

func (l linkInfo) Name() string       { return l.name }
func (l linkInfo) Size() int64        { return 0 }
func (l linkInfo) Mode() fs.FileMode  { return fs.ModeSymlink }
func (l linkInfo) ModTime() time.Time { return time.Time{} }
func (l linkInfo) IsDir() bool        { return false }
func (l linkInfo) Sys() any           { return nil }
