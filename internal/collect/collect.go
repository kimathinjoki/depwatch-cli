// Package collect takes the inventory of a part: it walks the folder, reads every dependency file,
// reads the edges, runtimes and images, and puts it all in one inventory.Inventory.
package collect

import (
	"context"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	scalibrfs "github.com/google/osv-scalibr/fs"

	"github.com/kimathinjoki/depwatch-cli/internal/config"
	"github.com/kimathinjoki/depwatch-cli/internal/discover"
	"github.com/kimathinjoki/depwatch-cli/internal/extract"
	"github.com/kimathinjoki/depwatch-cli/internal/graph"
	"github.com/kimathinjoki/depwatch-cli/internal/image"
	"github.com/kimathinjoki/depwatch-cli/internal/inventory"
)

// Options say what to read.
type Options struct {
	Root string
	// Images to read: local tarballs or registry references.
	Images []string
	// RootFS are folders laid out like a root filesystem whose package databases are read.
	RootFS []string
	// PullImages lets the collector pull base images named in depwatch.yml and Dockerfiles. Off for
	// depwatch inventory, which makes no network call; those images are then listed as not read.
	PullImages bool
	CLIVersion string
	Now        func() time.Time
	// TakenBy is "cli" (default) or "github" when a server fetched the files; Commit and Branch then
	// say where from, for a folder that is not a git checkout.
	TakenBy string
	Commit  string
	Branch  string
}

// Take takes the inventory. A depwatch.yml problem is returned as *config.Error.
func Take(ctx context.Context, o Options) (*inventory.Inventory, *config.Config, error) {
	root, err := filepath.Abs(o.Root)
	if err != nil {
		return nil, nil, err
	}
	cfg, err := config.Load(root)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	inv := &inventory.Inventory{
		SchemaVersion: inventory.SchemaVersion,
		CLIVersion:    o.CLIVersion,
		TakenAt:       now().UTC().Format(time.RFC3339),
		TakenBy:       "cli",
		Part:          gitPart(root),
	}
	if o.TakenBy != "" {
		inv.TakenBy = o.TakenBy
	}
	if o.Commit != "" {
		inv.Part.Commit = o.Commit
	}
	if o.Branch != "" {
		inv.Part.Branch = o.Branch
	}
	inv.Part.ProductionBranch = cfg.ProductionBranch

	fsys := scalibrfs.DirFS(root)
	walked, err := discover.WalkRoot(fsys, root, cfg.IgnoredDirs())
	if err != nil {
		return nil, nil, err
	}
	files, notFollowed := splitLinks(walked)
	res, err := extract.Project(ctx, root, files)
	if err != nil {
		return nil, nil, err
	}
	inv.FilesRead = res.FilesRead
	inv.FilesNotRead = append(res.FilesNotRead, notFollowed...)
	inv.Unsupported = res.Unsupported
	inv.Unpinned = res.Unpinned
	inv.Packages = packages(fsys, res)

	// Runtimes from version files and depwatch.yml.
	var fromFiles []inventory.Runtime
	for _, f := range files {
		if config.VersionFiles[path.Base(f.Path)] {
			raw, err := fs.ReadFile(fsys, f.Path)
			if err != nil {
				inv.FilesNotRead = append(inv.FilesNotRead, inventory.FileNotRead{Path: f.Path, Reason: err.Error()})
				continue
			}
			fromFiles = append(fromFiles, config.ReadVersionFile(f.Path, raw)...)
		}
	}
	fromConfig := cfg.FromConfig()
	inv.Runtimes = append(append([]inventory.Runtime{}, fromConfig...), fromFiles...)
	inv.Conflicts = config.Conflicts(fromConfig, fromFiles)

	// Images and filesystems.
	readImage := func(ref string) {
		r := image.ReadImage(ctx, ref)
		inv.Images = append(inv.Images, r.Image)
		inv.OSPackages = append(inv.OSPackages, r.Packages...)
		inv.FilesRead = append(inv.FilesRead, r.FilesRead...)
		inv.FilesNotRead = append(inv.FilesNotRead, r.FilesNotRead...)
	}
	for _, ref := range o.Images {
		readImage(ref)
	}
	for _, dir := range o.RootFS {
		label := dir
		if rel, err := filepath.Rel(root, dir); err == nil && !strings.HasPrefix(rel, "..") {
			label = filepath.ToSlash(rel)
		}
		r, err := image.ReadFS(ctx, dir, label)
		if err != nil {
			inv.FilesNotRead = append(inv.FilesNotRead, inventory.FileNotRead{Path: label, Reason: err.Error()})
			continue
		}
		if len(r.Packages) == 0 && len(r.FilesNotRead) == 0 {
			// Unlike an image, a folder is named by hand: one with no package database is most
			// likely the wrong folder, and nothing in it was checked.
			inv.FilesNotRead = append(inv.FilesNotRead, inventory.FileNotRead{Path: label,
				Reason: "no operating system package database found in this folder; nothing in it was checked"})
		}
		inv.OSPackages = append(inv.OSPackages, r.Packages...)
		inv.FilesRead = append(inv.FilesRead, r.FilesRead...)
		inv.FilesNotRead = append(inv.FilesNotRead, r.FilesNotRead...)
	}
	// Base images named in depwatch.yml and in Dockerfiles. When the built image itself was read
	// (--image), it already holds its base image's packages. A --rootfs folder does not stand in for
	// them: nothing says which image, if any, it was exported from.
	if len(o.Images) == 0 {
		for _, ref := range baseImages(fsys, files, cfg) {
			switch {
			case ref.Unresolved != "":
				inv.Images = append(inv.Images, inventory.Image{Reference: ref.Reference,
					Reason: "the base image uses the build argument " + ref.Unresolved + " with no default; pass --image to read the built image"})
			case o.PullImages:
				readImage(ref.Reference)
			default:
				inv.Images = append(inv.Images, inventory.Image{Reference: ref.Reference,
					Reason: "not pulled: depwatch inventory makes no network call; depwatch gate pulls it, or pass --image"})
			}
		}
	}
	sortInventory(inv)
	inv.Normalize()
	return inv, cfg, nil
}

// splitLinks takes out the symbolic links that were not followed. A link to a folder outside the
// part, or one that names a file depwatch would read (a dependency file, a Dockerfile, a version
// file), is listed as not read: what it leads to was never looked at. Other links (a README, an
// editor setting) are dropped, as they hold no dependencies.
func splitLinks(walked []discover.File) ([]discover.File, []inventory.FileNotRead) {
	var files []discover.File
	var notRead []inventory.FileNotRead
	for _, f := range walked {
		if f.NotFollowed == "" {
			files = append(files, f)
			continue
		}
		var size int64
		if f.Info != nil {
			size = f.Info.Size()
		}
		if f.Dir || extract.Wants(f.Path, size) || image.IsDockerfile(f.Path) || config.VersionFiles[path.Base(f.Path)] {
			notRead = append(notRead, inventory.FileNotRead{Path: f.Path, Reason: f.NotFollowed})
		}
	}
	return files, notRead
}

func baseImages(fsys fs.FS, files []discover.File, cfg *config.Config) []image.BaseImage {
	seen := map[string]bool{}
	var out []image.BaseImage
	add := func(b image.BaseImage) {
		if !seen[b.Reference] {
			seen[b.Reference] = true
			out = append(out, b)
		}
	}
	for _, ref := range cfg.Images {
		add(image.BaseImage{Reference: ref})
	}
	for _, f := range files {
		if !image.IsDockerfile(f.Path) {
			continue
		}
		raw, err := fs.ReadFile(fsys, f.Path)
		if err != nil {
			continue
		}
		if b, ok := image.FinalBase(string(raw)); ok {
			add(b)
		}
	}
	return out
}

// devGroupNames are the dependency group names extractors use for development only.
var devGroupNames = map[string]bool{"dev": true, "develop": true, "development": true, "test": true}

func scalibrScope(groups []string) (string, bool) {
	if len(groups) == 0 {
		return "", false
	}
	for _, g := range groups {
		if !devGroupNames[strings.ToLower(g)] {
			return inventory.ScopeProduction, true
		}
	}
	return inventory.ScopeDevelopment, true
}

func packages(fsys fs.FS, res *extract.Result) []inventory.Package {
	graphs := map[string]*graph.Graph{}
	resolved := map[string]map[string]graph.Info{}
	graphFor := func(file string) (*graph.Graph, map[string]graph.Info) {
		if g, ok := graphs[file]; ok {
			return g, resolved[file]
		}
		var g *graph.Graph
		if graph.Supported(file) {
			if raw, err := fs.ReadFile(fsys, file); err == nil {
				sibling := func(name string) ([]byte, bool) {
					b, err := fs.ReadFile(fsys, path.Join(path.Dir(file), name))
					return b, err == nil
				}
				g, _ = graph.Read(file, raw, sibling)
			}
		}
		graphs[file] = g
		if g != nil {
			resolved[file] = g.Resolve()
		}
		return g, resolved[file]
	}

	seen := map[string]bool{}
	var out []inventory.Package
	for _, f := range res.Found {
		p := f.Pkg
		ip := inventory.Package{
			Ecosystem:  string(p.Ecosystem().Ecosystem),
			Name:       p.Name,
			Version:    p.Version,
			SourceFile: f.File,
			Relation:   inventory.RelationUnknown,
			Paths:      [][]inventory.Step{},
		}
		if ip.Ecosystem == "" {
			ip.Ecosystem = extract.EcosystemOfReader(f.Reader)
		}
		if strings.HasPrefix(ip.Version, "range:") {
			ip.Range = strings.TrimPrefix(ip.Version, "range:")
			ip.Version = ""
		}
		if u := p.PURL(); u != nil && ip.Version != "" {
			ip.PURL = u.String()
		}
		key := f.File + "|" + ip.Ecosystem + "|" + ip.Name + "|" + ip.Version + "|" + ip.Range
		if seen[key] {
			continue
		}
		seen[key] = true

		groupScope, groupsKnown := "", false
		if dg, ok := p.Metadata.(osv.DepGroups); ok {
			groupScope, groupsKnown = scalibrScope(dg.DepGroups())
		}
		g, infos := graphFor(f.File)
		placed := false
		if g != nil && g.EdgesRecorded {
			if k, ok := g.Lookup(p.Name, p.Version); ok {
				if info := infos[k]; info.Reached {
					ip.Relation = info.Relation
					ip.Paths = toSteps(info.Paths)
					ip.MorePaths = info.MorePaths
					ip.PathsRecorded = true
					if g.RootsKnown {
						ip.Scope, ip.ScopeRecorded = info.Scope, true
					}
					placed = true
				}
			}
		}
		if !placed && g != nil && !g.EdgesRecorded {
			norm := g.NormalizeName
			if norm == nil {
				norm = func(s string) string { return s }
			}
			rel := g.Relations[norm(p.Name)]
			if rel == "" {
				rel = g.Relations["*"]
			}
			if rel != "" {
				ip.Relation = rel
			}
			if rel == inventory.RelationDirect {
				ip.Paths = [][]inventory.Step{{{Name: p.Name, Version: p.Version}}}
				ip.PathsRecorded = true
			}
			if g.DevNames[p.Name] {
				ip.Scope, ip.ScopeRecorded = inventory.ScopeDevelopment, true
			}
		}
		if ip.Scope == "" && groupsKnown {
			ip.Scope, ip.ScopeRecorded = groupScope, true
		}
		if ip.Scope == "" {
			// The file does not say: production, the louder answer, marked as not recorded.
			ip.Scope, ip.ScopeRecorded = inventory.ScopeProduction, false
		}
		out = append(out, ip)
	}
	out = append(out, res.Ranged...)
	return out
}

func toSteps(paths [][]graph.Node) [][]inventory.Step {
	out := make([][]inventory.Step, 0, len(paths))
	for _, p := range paths {
		steps := make([]inventory.Step, len(p))
		for i, n := range p {
			steps[i] = inventory.Step{Name: n.Name, Version: n.Version}
		}
		out = append(out, steps)
	}
	return out
}

func sortInventory(inv *inventory.Inventory) {
	sort.SliceStable(inv.Packages, func(i, j int) bool {
		a, b := inv.Packages[i], inv.Packages[j]
		if a.SourceFile != b.SourceFile {
			return a.SourceFile < b.SourceFile
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Version < b.Version
	})
	sort.SliceStable(inv.OSPackages, func(i, j int) bool {
		a, b := inv.OSPackages[i], inv.OSPackages[j]
		if a.SourceFile != b.SourceFile {
			return a.SourceFile < b.SourceFile
		}
		return a.Name < b.Name
	})
	sort.SliceStable(inv.FilesRead, func(i, j int) bool { return inv.FilesRead[i].Path < inv.FilesRead[j].Path })
	sort.SliceStable(inv.FilesNotRead, func(i, j int) bool { return inv.FilesNotRead[i].Path < inv.FilesNotRead[j].Path })
}

// gitPart reads the commit and branch from the folder's git metadata, without running git.
// In CI on a detached head, the branch comes from the CI's environment.
func gitPart(root string) inventory.Part {
	part := inventory.Part{Root: filepath.Base(root)}
	gitDir := ""
	for d := root; ; d = filepath.Dir(d) {
		if st, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			if st.IsDir() {
				gitDir = filepath.Join(d, ".git")
			} else if raw, err := os.ReadFile(filepath.Join(d, ".git")); err == nil {
				// a worktree: "gitdir: <path>"
				gd := strings.TrimSpace(strings.TrimPrefix(string(raw), "gitdir:"))
				if !filepath.IsAbs(gd) {
					gd = filepath.Join(d, gd)
				}
				gitDir = gd
			}
			break
		}
		if filepath.Dir(d) == d {
			break
		}
	}
	if gitDir == "" {
		return part
	}
	head, err := os.ReadFile(filepath.Join(gitDir, "HEAD"))
	if err != nil {
		return part
	}
	h := strings.TrimSpace(string(head))
	if strings.HasPrefix(h, "ref: ") {
		ref := strings.TrimPrefix(h, "ref: ")
		part.Branch = strings.TrimPrefix(ref, "refs/heads/")
		part.Commit = readRef(gitDir, ref)
	} else {
		part.Commit = h
		for _, env := range []string{"GITHUB_HEAD_REF", "GITHUB_REF_NAME", "CI_COMMIT_REF_NAME", "BUILDKITE_BRANCH"} {
			if v := os.Getenv(env); v != "" {
				part.Branch = v
				break
			}
		}
	}
	return part
}

func readRef(gitDir, ref string) string {
	commonDir := gitDir
	if raw, err := os.ReadFile(filepath.Join(gitDir, "commondir")); err == nil {
		cd := strings.TrimSpace(string(raw))
		if !filepath.IsAbs(cd) {
			cd = filepath.Join(gitDir, cd)
		}
		commonDir = cd
	}
	for _, dir := range []string{gitDir, commonDir} {
		if raw, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(ref))); err == nil {
			return strings.TrimSpace(string(raw))
		}
	}
	if raw, err := os.ReadFile(filepath.Join(commonDir, "packed-refs")); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			f := strings.Fields(line)
			if len(f) == 2 && f[1] == ref {
				return f[0]
			}
		}
	}
	return ""
}
