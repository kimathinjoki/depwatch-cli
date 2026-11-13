package config

import (
	"bufio"
	"path"
	"sort"
	"strings"

	"github.com/kimathinjoki/depwatch-cli/internal/inventory"
)

// VersionFiles are the files that state a runtime version, by base name.
var VersionFiles = map[string]bool{
	".ruby-version":   true,
	".nvmrc":          true,
	".node-version":   true,
	".python-version": true,
	".tool-versions":  true,
}

// toolNames maps .tool-versions (asdf, mise) names to depwatch's runtime names.
var toolNames = map[string]string{
	"nodejs": "node", "node": "node", "ruby": "ruby", "python": "python", "golang": "go", "go": "go",
	"java": "java", "php": "php", "rust": "rust", "elixir": "elixir", "erlang": "erlang",
	"dotnet": "dotnet", "dotnet-core": "dotnet", "deno": "deno", "bun": "bun",
	"postgres": "postgres", "postgresql": "postgres", "mysql": "mysql", "redis": "redis",
}

var databaseNames = map[string]bool{"postgres": true, "mysql": true, "redis": true, "mariadb": true, "mongodb": true, "sqlite": true}

// ReadVersionFile reads the runtimes one version file states. The value is kept as written apart
// from a leading "v" or "ruby-"; an alias such as lts/iron is listed as it is, never resolved.
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
		return one("node", strings.TrimPrefix(firstLine(), "v"))
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

// FromConfig lists the runtimes, databases and hosting runtimes depwatch.yml states.
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
	for _, h := range c.Hosting {
		out = append(out, inventory.Runtime{Kind: inventory.KindHosting, Name: h.Name, Version: string(h.Version), SourceFile: c.Path})
	}
	return out
}

// Conflicts lists every runtime whose sources state different versions: depwatch.yml against a
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
		versions := map[string]bool{}
		for _, r := range g.list {
			versions[r.Version] = true
		}
		if len(versions) > 1 {
			out = append(out, inventory.Conflict{Name: g.list[0].Name, Runtimes: g.list})
		}
	}
	return out
}
