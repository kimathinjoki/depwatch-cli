package extract

import (
	"encoding/json"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/kimathinjoki/watchdep-cli/internal/discover"
	"github.com/kimathinjoki/watchdep-cli/internal/gemfile"
	"github.com/kimathinjoki/watchdep-cli/internal/inventory"
)

// manifestRule says which lockfiles pin a manifest. A manifest with none of them in its folder or a
// folder above it (workspaces keep one lockfile at the top) is unpinned.
type manifestRule struct {
	ecosystem string
	locks     []string
}

var manifestRules = map[string]manifestRule{
	"package.json":     {"npm", []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb"}},
	"Gemfile":          {"RubyGems", []string{"Gemfile.lock"}},
	"gems.rb":          {"RubyGems", []string{"gems.locked"}},
	"composer.json":    {"Packagist", []string{"composer.lock"}},
	"Pipfile":          {"PyPI", []string{"Pipfile.lock"}},
	"pyproject.toml":   {"PyPI", []string{"poetry.lock", "uv.lock", "pdm.lock", "pylock.toml", "Pipfile.lock", "requirements.txt"}},
	"Cargo.toml":       {"crates.io", []string{"Cargo.lock"}},
	"pubspec.yaml":     {"Pub", []string{"pubspec.lock"}},
	"mix.exs":          {"Hex", []string{"mix.lock"}},
	"Package.swift":    {"SwiftURL", []string{"Package.resolved"}},
	"Podfile":          {"CocoaPods", []string{"Podfile.lock"}},
	"build.gradle":     {"Maven", []string{"gradle.lockfile"}},
	"build.gradle.kts": {"Maven", []string{"gradle.lockfile"}},
}

func findUnpinned(fsys fs.FS, files []discover.File, res *Result) {
	present := map[string]bool{}
	for _, f := range files {
		present[f.Path] = true
	}
	hasLock := func(dir string, locks []string) bool {
		for d := dir; ; d = path.Dir(d) {
			for _, l := range locks {
				if present[path.Join(d, l)] {
					return true
				}
			}
			if d == "." {
				return false
			}
		}
	}
	for _, f := range files {
		rule, ok := manifestRules[path.Base(f.Path)]
		if !ok || hasLock(path.Dir(f.Path), rule.locks) {
			continue
		}
		pkgs, declares := readRanges(fsys, f.Path, rule.ecosystem)
		if !declares {
			continue // a package.json with no dependencies at all pins nothing and needs nothing
		}
		res.Unpinned = append(res.Unpinned, inventory.Unpinned{Path: f.Path, Ecosystem: rule.ecosystem})
		res.Ranged = append(res.Ranged, pkgs...)
	}
	// Manifest readers that produced packages without a lockfile give ranges, not versions.
	for i := range res.Found {
		f := &res.Found[i]
		if manifestReaders[f.Reader] && !exactVersion(f.Pkg.Version) {
			f.Pkg.Version = "range:" + f.Pkg.Version
		}
	}
}

var exactRe = regexp.MustCompile(`^v?\d+(\.\d+)*([-+.][0-9A-Za-z.\-+]*)?$`)

func exactVersion(v string) bool { return exactRe.MatchString(v) }

// readRanges lists the dependencies a manifest declares, with their ranges. The second result is
// false when the manifest declares no dependencies at all.
func readRanges(fsys fs.FS, p, eco string) ([]inventory.Package, bool) {
	raw, err := fs.ReadFile(fsys, p)
	if err != nil {
		return nil, true
	}
	var out []inventory.Package
	add := func(name, rng, scope string) {
		out = append(out, inventory.Package{
			Ecosystem: eco, Name: name, Range: rng, Scope: scope, ScopeRecorded: true,
			Relation: inventory.RelationDirect, SourceFile: p,
			Paths: [][]inventory.Step{{{Name: name}}}, PathsRecorded: true,
		})
	}
	switch path.Base(p) {
	case "package.json":
		var m struct {
			Dependencies         map[string]string `json:"dependencies"`
			DevDependencies      map[string]string `json:"devDependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
			PeerDependencies     map[string]string `json:"peerDependencies"`
		}
		if json.Unmarshal(raw, &m) != nil {
			return nil, true
		}
		for _, n := range sortedKeys(m.Dependencies) {
			add(n, m.Dependencies[n], inventory.ScopeProduction)
		}
		for _, n := range sortedKeys(m.OptionalDependencies) {
			add(n, m.OptionalDependencies[n], inventory.ScopeProduction)
		}
		for _, n := range sortedKeys(m.DevDependencies) {
			add(n, m.DevDependencies[n], inventory.ScopeDevelopment)
		}
		return out, len(m.Dependencies)+len(m.DevDependencies)+len(m.OptionalDependencies)+len(m.PeerDependencies) > 0
	case "composer.json":
		var m struct {
			Require    map[string]string `json:"require"`
			RequireDev map[string]string `json:"require-dev"`
		}
		if json.Unmarshal(raw, &m) != nil {
			return nil, true
		}
		for _, n := range sortedKeys(m.Require) {
			if n == "php" || strings.HasPrefix(n, "ext-") {
				continue
			}
			add(n, m.Require[n], inventory.ScopeProduction)
		}
		for _, n := range sortedKeys(m.RequireDev) {
			add(n, m.RequireDev[n], inventory.ScopeDevelopment)
		}
		return out, len(m.Require)+len(m.RequireDev) > 0
	case "Gemfile", "gems.rb":
		for _, g := range gemfile.Parse(string(raw)) {
			scope := inventory.ScopeProduction
			if g.DevOnly {
				scope = inventory.ScopeDevelopment
			}
			add(g.Name, g.Requirement, scope)
		}
		return out, true
	}
	return out, true
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
