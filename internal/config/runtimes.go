package config

import (
	"bufio"
	"path"
	"sort"
	"strings"

	"github.com/kimathinjoki/watchdep-cli/internal/inventory"
)

// VersionFiles are the files that state a runtime version, by base name.
var VersionFiles = map[string]bool{
	".ruby-version":   true,
	".nvmrc":          true,
	".node-version":   true,
	".python-version": true,
	".tool-versions":  true,
}

// IsRuntimeFile reports whether watchdep reads a file for the runtimes it states, besides
// Dockerfiles and watchdep.yml: a version file, a manifest, toolchain or build file, or a Compose file.
func IsRuntimeFile(p string) bool {
	b := path.Base(p)
	return VersionFiles[b] || manifestFiles[b] || IsComposeFile(p)
}

// toolNames maps .tool-versions (asdf, mise) names to watchdep's runtime names.
var toolNames = map[string]string{
	"nodejs": "node", "node": "node", "ruby": "ruby", "python": "python", "golang": "go", "go": "go",
	"java": "java", "php": "php", "rust": "rust", "elixir": "elixir", "erlang": "erlang",
	"dotnet": "dotnet", "dotnet-core": "dotnet", "deno": "deno", "bun": "bun",
	"postgres": "postgres", "postgresql": "postgres", "mysql": "mysql", "redis": "redis",
}

var databaseNames = map[string]bool{"postgres": true, "mysql": true, "redis": true, "mariadb": true, "mongodb": true, "sqlite": true}

// nodeLTS maps Node's long-term support codenames, as nvm writes them (lts/iron), to their major
// release. A codename always names the same major; lts/* and node move, so they stay as written.
var nodeLTS = map[string]string{
	"argon": "4", "boron": "6", "carbon": "8", "dubnium": "10", "erbium": "12", "fermium": "14",
	"gallium": "16", "hydrogen": "18", "iron": "20", "jod": "22", "krypton": "24",
}

// ReadVersionFile reads the runtimes one version file states. The value is kept as written apart
// from a leading "v" or "ruby-", and a Node LTS codename (lts/iron), which is its major (20).
func ReadVersionFile(file string, content []byte) []inventory.Runtime {
	base := path.Base(file)
	firstLine := func() string {
		for _, l := range strings.Split(string(content), "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				return l
			}
		}
		return ""
	}
	one := func(name, v string) []inventory.Runtime {
		if v == "" {
			return nil
		}
		return []inventory.Runtime{{Kind: inventory.KindRuntime, Name: name, Version: v, SourceFile: file}}
	}
	switch base {
	case ".ruby-version":
		return one("ruby", strings.TrimPrefix(firstLine(), "ruby-"))
	case ".nvmrc", ".node-version":
		v := strings.TrimPrefix(firstLine(), "v")
		if major, ok := nodeLTS[strings.ToLower(strings.TrimPrefix(v, "lts/"))]; ok && strings.HasPrefix(v, "lts/") {
			v = major
		}
		return one("node", v)
	case ".python-version":
		return one("python", strings.TrimPrefix(firstLine(), "python-"))
	case ".tool-versions":
		var out []inventory.Runtime
		sc := bufio.NewScanner(strings.NewReader(string(content)))
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if i := strings.Index(line, "#"); i >= 0 {
				line = strings.TrimSpace(line[:i])
			}
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			name, ok := toolNames[f[0]]
			if !ok {
				name = f[0]
			}
			kind := inventory.KindRuntime
			if databaseNames[name] {
				kind = inventory.KindDatabase
			}
			out = append(out, inventory.Runtime{Kind: kind, Name: name, Version: strings.TrimPrefix(f[1], "v"), SourceFile: file})
		}
		return out
	}
	return nil
}

// FromConfig lists the runtimes, databases and hosting runtimes watchdep.yml states, and those its
// images run.
func (c *Config) FromConfig() []inventory.Runtime {
	var out []inventory.Runtime
	names := make([]string, 0, len(c.Runtimes))
	for n := range c.Runtimes {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		name := n
		if t, ok := toolNames[n]; ok {
			name = t
		}
		out = append(out, inventory.Runtime{Kind: inventory.KindRuntime, Name: name, Version: string(c.Runtimes[n]), SourceFile: c.Path})
	}
	for _, d := range c.Databases {
		name := strings.ToLower(d.Engine)
		if t, ok := toolNames[name]; ok {
			name = t
		}
		out = append(out, inventory.Runtime{Kind: inventory.KindDatabase, Name: name, Version: string(d.Version), SourceFile: c.Path})
	}
	for _, ref := range c.Images {
		if r, ok := RuntimeFromImage(ref, c.Path); ok {
			out = append(out, r)
		}
	}
	for _, h := range c.Hosting {
		out = append(out, inventory.Runtime{Kind: inventory.KindHosting, Name: h.Name, Version: string(h.Version), SourceFile: c.Path})
	}
	return out
}

// Conflicts lists every runtime whose sources state different releases: watchdep.yml against a
// version file, or two version files in one folder. Folders of a monorepo may run different
// versions, so files in different folders are not compared with each other. Both stay listed in
// the inventory; the conflict is reported so a person decides which one production runs.
func Conflicts(fromConfig, fromFiles []inventory.Runtime) []inventory.Conflict {
	type group struct {
		key  string
		list []inventory.Runtime
	}
	var groups []*group
	byKey := map[string]*group{}
	for _, r := range fromFiles {
		key := r.Kind + "|" + r.Name + "|" + path.Dir(r.SourceFile)
		g, ok := byKey[key]
		if !ok {
			g = &group{key: key}
			for _, c := range fromConfig {
				if c.Kind == r.Kind && c.Name == r.Name {
					g.list = append(g.list, c)
				}
			}
			byKey[key] = g
			groups = append(groups, g)
		}
		g.list = append(g.list, r)
	}
	var out []inventory.Conflict
	for _, g := range groups {
		if !sameRelease(g.list) {
			out = append(out, inventory.Conflict{Name: g.list[0].Name, Runtimes: g.list})
		}
	}
	return out
}

// sameRelease reports whether the versions agree: equal, or one a shorter form of the other, as 16 and
// 16.20.0 from FROM node:16 and an .nvmrc, but not 16 and 18 or 3.1 and 3.12.
func sameRelease(list []inventory.Runtime) bool {
	for i := range list {
		for j := i + 1; j < len(list); j++ {
			a, b := list[i].Version, list[j].Version
			if len(a) > len(b) {
				a, b = b, a
			}
			if a != b && !strings.HasPrefix(b, a+".") {
				return false
			}
		}
	}
	return true
}
