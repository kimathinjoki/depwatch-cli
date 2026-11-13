package graph

import (
	"bufio"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/kimathinjoki/depwatch-cli/internal/gemfile"
)

// Sibling reads a file beside the lockfile by name; ok is false when there is none.
type Sibling func(name string) (data []byte, ok bool)

// reader reads one kind of lockfile.
type reader func(lock []byte, sibling Sibling) (*Graph, error)

var readers = map[string]reader{
	"Gemfile.lock":        readGemfileLock,
	"gems.locked":         readGemfileLock,
	"package-lock.json":   readPackageLock,
	"npm-shrinkwrap.json": readPackageLock,
	"yarn.lock":           readYarnLock,
	"pnpm-lock.yaml":      readPnpmLock,
	"composer.lock":       readComposerLock,
	"poetry.lock":         readPoetryLock,
	"uv.lock":             readUvLock,
	"Cargo.lock":          readCargoLock,
	"packages.lock.json":  readNugetLock,
	"go.mod":              readGoMod,
	"pubspec.lock":        readPubspecLock,
	"Pipfile.lock":        readPipfileLock,
	"pom.xml":             readDirectOnly,
	"gradle.lockfile":     readGradleLock,
}

// Supported reports whether depwatch reads anything about edges or relations from this file.
func Supported(file string) bool {
	_, ok := readers[path.Base(file)]
	return ok
}

// Read reads the edges a lockfile records. It returns nil and no error for files depwatch reads no
// edges from; their packages' paths read "path not recorded".
func Read(file string, lock []byte, sibling Sibling) (*Graph, error) {
	r, ok := readers[path.Base(file)]
	if !ok {
		return nil, nil
	}
	return r(lock, sibling)
}

// ---- Ruby: Gemfile.lock ----

var (
	gemSpecRe = regexp.MustCompile(`^    (\S+) \(([^)]+)\)$`)
	gemDepRe  = regexp.MustCompile(`^      (\S+)(?: \(.*\))?$`)
	gemTopRe  = regexp.MustCompile(`^  (\S+?)!?(?: \(.*\))?$`)
	platRe    = regexp.MustCompile(`-(x86|x64|arm|aarch64|universal|java|mswin|mingw|darwin|linux|ruby).*$`)
)

func readGemfileLock(lock []byte, sibling Sibling) (*Graph, error) {
	g := newGraph()
	byName := map[string]string{}
	deps := map[string][]string{}
	var direct []string
	section := ""
	current := ""
	sc := bufio.NewScanner(strings.NewReader(string(lock)))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			section = line
			current = ""
			continue
		}
		switch section {
		case "GEM", "GIT", "PATH", "PLUGIN SOURCE":
			if m := gemSpecRe.FindStringSubmatch(line); m != nil {
				name, version := m[1], platRe.ReplaceAllString(m[2], "")
				if _, seen := byName[name]; !seen {
					byName[name] = g.addNode(name, version)
				}
				current = name
			} else if m := gemDepRe.FindStringSubmatch(line); m != nil && current != "" {
				deps[current] = append(deps[current], m[1])
			}
		case "DEPENDENCIES":
			if m := gemTopRe.FindStringSubmatch(line); m != nil {
				direct = append(direct, m[1])
			}
		}
	}
	if len(byName) == 0 {
		return nil, fmt.Errorf("no gem specs found")
	}
	for from, tos := range deps {
		for _, t := range tos {
			if tk, ok := byName[t]; ok {
				g.addEdge(byName[from], tk)
			}
		}
	}
	dev := map[string]bool{}
	manifest, ok := sibling("Gemfile")
	if !ok {
		manifest, ok = sibling("gems.rb")
	}
	if ok {
		for _, gem := range gemfile.Parse(string(manifest)) {
			dev[gem.Name] = gem.DevOnly
		}
	} else {
		g.RootsKnown = false
	}
	for _, name := range direct {
		if k, ok := byName[name]; ok {
			g.addRoot(k, dev[name])
		}
	}
	return g, nil
}

// ---- JavaScript: package-lock.json ----

type npmLock struct {
	LockfileVersion int                       `json:"lockfileVersion"`
	Packages        map[string]npmLockPackage `json:"packages"`
	Dependencies    map[string]npmV1Dep       `json:"dependencies"`
}

type npmLockPackage struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Link                 bool              `json:"link"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type npmV1Dep struct {
	Version      string              `json:"version"`
	Dev          bool                `json:"dev"`
	Requires     map[string]string   `json:"requires"`
	Dependencies map[string]npmV1Dep `json:"dependencies"`
}

func readPackageLock(lock []byte, _ Sibling) (*Graph, error) {
	var l npmLock
	if err := json.Unmarshal(lock, &l); err != nil {
		return nil, err
	}
	if len(l.Packages) > 0 {
		return readNpmPackages(l.Packages), nil
	}
	return readNpmV1(l.Dependencies), nil
}

func npmNameFromPath(p string) string {
	i := strings.LastIndex(p, "node_modules/")
	if i < 0 {
		return ""
	}
	return p[i+len("node_modules/"):]
}

func readNpmPackages(pkgs map[string]npmLockPackage) *Graph {
	g := newGraph()
	keyOf := map[string]string{} // install path to node key
	for p, pkg := range pkgs {
		if p == "" || pkg.Link || !strings.Contains(p, "node_modules/") {
			continue
		}
		name := npmNameFromPath(p)
		if pkg.Name != "" && pkg.Name != name {
			name = pkg.Name // an alias installs one package under another name
		}
		keyOf[p] = g.addNode(name, pkg.Version)
	}
	resolve := func(from, dep string) (string, bool) {
		// Node's resolution: the nearest node_modules folder up from the requiring package.
		base := from
		for {
			cand := "node_modules/" + dep
			if base != "" {
				cand = base + "/node_modules/" + dep
			}
			if pkg, ok := pkgs[cand]; ok {
				if pkg.Link {
					if k, ok := keyOf[pkg.Resolved]; ok {
						return k, true
					}
					return "", false
				}
				k, ok := keyOf[cand]
				return k, ok
			}
			if base == "" {
				return "", false
			}
			i := strings.LastIndex(base, "/node_modules/")
			if i < 0 {
				if strings.HasPrefix(base, "node_modules/") {
					base = ""
				} else {
					// a workspace folder: its parent is the root
					base = ""
				}
				continue
			}
			base = base[:i]
		}
	}
	for p, pkg := range pkgs {
		from, isNode := keyOf[p]
		for _, deps := range []map[string]string{pkg.Dependencies, pkg.OptionalDependencies, pkg.PeerDependencies} {
			for dep := range deps {
				to, ok := resolve(p, dep)
				if !ok {
					continue
				}
				if isNode {
					g.addEdge(from, to)
				} else if p == "" || !strings.Contains(p, "node_modules/") {
					g.addRoot(to, false) // the root or a workspace folder
				}
			}
		}
		if !isNode && (p == "" || !strings.Contains(p, "node_modules/")) {
			for dep := range pkg.DevDependencies {
				if to, ok := resolve(p, dep); ok {
					g.addRoot(to, true)
				}
			}
		}
	}
	return g
}

func readNpmV1(deps map[string]npmV1Dep) *Graph {
	g := newGraph()
	type scope struct {
		parent *scope
		deps   map[string]npmV1Dep
		keys   map[string]string
	}
	var walk func(s *scope)
	resolve := func(s *scope, name string) (string, bool) {
		for c := s; c != nil; c = c.parent {
			if k, ok := c.keys[name]; ok {
				return k, true
			}
		}
		return "", false
	}
	var all []func()
	walk = func(s *scope) {
		s.keys = map[string]string{}
		for name, d := range s.deps {
			s.keys[name] = g.addNode(name, d.Version)
		}
		for name, d := range s.deps {
			child := &scope{parent: s, deps: d.Dependencies}
			walk(child)
			from := s.keys[name]
			reqs := d.Requires
			all = append(all, func() {
				for r := range reqs {
					if to, ok := resolve(child, r); ok {
						g.addEdge(from, to)
					}
				}
			})
		}
	}
	top := &scope{deps: deps}
	walk(top)
	for _, f := range all {
		f()
	}
	// v1 records no root manifest in the lockfile: a top-level package nothing requires is direct.
	used := map[string]bool{}
	for _, tos := range g.Edges {
		for _, t := range tos {
			used[t] = true
		}
	}
	for name, d := range deps {
		if k := top.keys[name]; !used[k] {
			g.addRoot(k, d.Dev)
		}
	}
	return g
}

// ---- JavaScript: yarn.lock (classic and berry) ----

func readYarnLock(lock []byte, sibling Sibling) (*Graph, error) {
	text := string(lock)
	var entries map[string]yarnEntry
	var err error
	if strings.Contains(text, "__metadata:") {
		entries, err = parseYarnBerry(lock)
	} else {
		entries, err = parseYarnClassic(text)
	}
	if err != nil {
		return nil, err
	}
	g := newGraph()
	byDescriptor := map[string]string{}
	byName := map[string][]string{}
	for desc, e := range entries {
		if strings.Contains(desc, "@workspace:") || strings.Contains(e.version, "use.local") {
			continue
		}
		name := descriptorName(desc)
		k := g.addNode(name, e.version)
		byDescriptor[normalizeDescriptor(desc)] = k
		byName[name] = appendUnique(byName[name], k)
	}
	find := func(name, rng string) (string, bool) {
		if k, ok := byDescriptor[normalizeDescriptor(name+"@"+rng)]; ok {
			return k, true
		}
		if ks := byName[name]; len(ks) == 1 {
			return ks[0], true
		}
		return "", false
	}
	for desc, e := range entries {
		if strings.Contains(desc, "@workspace:") {
			continue
		}
		from := byDescriptor[normalizeDescriptor(desc)]
		for dep, rng := range e.deps {
			if to, ok := find(dep, rng); ok {
				g.addEdge(from, to)
			}
		}
	}
	if manifest, ok := sibling("package.json"); ok {
		var m struct {
			Dependencies         map[string]string `json:"dependencies"`
			DevDependencies      map[string]string `json:"devDependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
		}
		if json.Unmarshal(manifest, &m) == nil {
			for n, r := range m.Dependencies {
				if k, ok := find(n, r); ok {
					g.addRoot(k, false)
				}
			}
			for n, r := range m.OptionalDependencies {
				if k, ok := find(n, r); ok {
					g.addRoot(k, false)
				}
			}
			for n, r := range m.DevDependencies {
				if k, ok := find(n, r); ok {
					g.addRoot(k, true)
				}
			}
		}
		// Workspaces declare their own dependencies in berry's lockfile.
		for desc, e := range entries {
			if strings.Contains(desc, "@workspace:") && !strings.HasSuffix(desc, "@workspace:.") {
				for dep, rng := range e.deps {
					if k, ok := find(dep, rng); ok {
						g.addRoot(k, false)
					}
				}
			}
		}
	} else {
		g.inferRoots()
	}
	return g, nil
}

type yarnEntry struct {
	version string
	deps    map[string]string
}

func parseYarnClassic(text string) (map[string]yarnEntry, error) {
	out := map[string]yarnEntry{}
	var keys []string
	var cur *yarnEntry
	inDeps := false
	flush := func() {
		if cur != nil {
			for _, k := range keys {
				out[k] = *cur
			}
		}
	}
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1024*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		trim := strings.TrimSpace(line)
		switch {
		case indent == 0:
			flush()
			trim = strings.TrimSuffix(trim, ":")
			keys = nil
			for _, part := range strings.Split(trim, ",") {
				keys = append(keys, strings.Trim(strings.TrimSpace(part), `"`))
			}
			cur = &yarnEntry{deps: map[string]string{}}
			inDeps = false
		case indent == 2 && cur != nil:
			inDeps = trim == "dependencies:" || trim == "optionalDependencies:"
			if strings.HasPrefix(trim, "version ") {
				cur.version = strings.Trim(strings.TrimPrefix(trim, "version "), `"`)
			}
		case indent == 4 && inDeps && cur != nil:
			name, rng, ok := splitYarnDep(trim)
			if ok {
				cur.deps[name] = rng
			}
		}
	}
	flush()
	if len(out) == 0 {
		return nil, fmt.Errorf("no entries found")
	}
	return out, nil
}

func splitYarnDep(s string) (string, string, bool) {
	// `"@babel/highlight" "^7.12.13"` or `lodash "^4.17.21"`
	s = strings.TrimSpace(s)
	var name string
	if strings.HasPrefix(s, `"`) {
		end := strings.Index(s[1:], `"`)
		if end < 0 {
			return "", "", false
		}
		name = s[1 : end+1]
		s = s[end+2:]
	} else {
		i := strings.Index(s, " ")
		if i < 0 {
			return "", "", false
		}
		name = s[:i]
		s = s[i:]
	}
	return name, strings.Trim(strings.TrimSpace(s), `"`), true
}

func parseYarnBerry(lock []byte) (map[string]yarnEntry, error) {
	var raw map[string]struct {
		Version              string            `yaml:"version"`
		Dependencies         map[string]string `yaml:"dependencies"`
		OptionalDependencies map[string]string `yaml:"optionalDependencies"`
	}
	if err := yaml.Unmarshal(lock, &raw); err != nil {
		return nil, err
	}
	out := map[string]yarnEntry{}
	for keyList, e := range raw {
		if keyList == "__metadata" {
			continue
		}
		deps := map[string]string{}
		for k, v := range e.Dependencies {
			deps[k] = v
		}
		for k, v := range e.OptionalDependencies {
			deps[k] = v
		}
		for _, k := range strings.Split(keyList, ",") {
			out[strings.TrimSpace(k)] = yarnEntry{version: e.Version, deps: deps}
		}
	}
	return out, nil
}

// descriptorName takes "name@range" (the name may start with @scope/) and returns the name.
func descriptorName(desc string) string {
	if strings.HasPrefix(desc, "@") {
		if i := strings.Index(desc[1:], "@"); i >= 0 {
			return desc[:i+1]
		}
		return desc
	}
	if i := strings.Index(desc, "@"); i >= 0 {
		return desc[:i]
	}
	return desc
}

// normalizeDescriptor drops berry's default npm: protocol so classic and berry ranges compare.
func normalizeDescriptor(desc string) string {
	name := descriptorName(desc)
	rng := strings.TrimPrefix(desc[len(name):], "@")
	rng = strings.TrimPrefix(rng, "npm:")
	return name + "@" + rng
}

// ---- JavaScript: pnpm-lock.yaml ----

type pnpmImporter struct {
	Dependencies         map[string]any `yaml:"dependencies"`
	DevDependencies      map[string]any `yaml:"devDependencies"`
	OptionalDependencies map[string]any `yaml:"optionalDependencies"`
}

type pnpmPackage struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
	Version              string            `yaml:"version"`
	Name                 string            `yaml:"name"`
}

type pnpmLock struct {
	LockfileVersion any                     `yaml:"lockfileVersion"`
	Importers       map[string]pnpmImporter `yaml:"importers"`
	Packages        map[string]pnpmPackage  `yaml:"packages"`
	Snapshots       map[string]pnpmPackage  `yaml:"snapshots"`
	pnpmImporter    `yaml:",inline"`
}

var peerSuffixRe = regexp.MustCompile(`\(.*$|_.*$`)

func readPnpmLock(lock []byte, _ Sibling) (*Graph, error) {
	var l pnpmLock
	if err := yaml.Unmarshal(lock, &l); err != nil {
		return nil, err
	}
	g := newGraph()
	entries := l.Snapshots
	if len(entries) == 0 {
		entries = l.Packages
	}
	keyOf := map[string]string{} // "name@version" (without peers) to node key
	parse := func(id string) (string, string) {
		id = strings.TrimPrefix(id, "/")
		id = peerSuffixRe.ReplaceAllString(id, "")
		// v5 used name/version; v6 and later use name@version
		if !strings.Contains(strings.TrimPrefix(id, "@"), "@") {
			i := strings.LastIndex(id, "/")
			if i > 0 {
				return id[:i], id[i+1:]
			}
		}
		name := descriptorName(id)
		return name, strings.TrimPrefix(id[len(name):], "@")
	}
	for id := range entries {
		name, version := parse(id)
		if name == "" || version == "" {
			continue
		}
		keyOf[name+"@"+version] = g.addNode(name, version)
	}
	ref := func(name, version string) (string, bool) {
		if strings.HasPrefix(version, "link:") || strings.HasPrefix(version, "file:") {
			return "", false
		}
		v := peerSuffixRe.ReplaceAllString(version, "")
		if strings.HasPrefix(v, "/") || strings.Contains(strings.TrimPrefix(v, "@"), "@") {
			// an aliased dependency points at another package id
			n, ver := parse(v)
			k, ok := keyOf[n+"@"+ver]
			return k, ok
		}
		k, ok := keyOf[name+"@"+v]
		return k, ok
	}
	for id, e := range entries {
		name, version := parse(id)
		from, ok := keyOf[name+"@"+version]
		if !ok {
			continue
		}
		for _, deps := range []map[string]string{e.Dependencies, e.OptionalDependencies} {
			for dn, dv := range deps {
				if to, ok := ref(dn, dv); ok {
					g.addEdge(from, to)
				}
			}
		}
	}
	importers := l.Importers
	if len(importers) == 0 {
		importers = map[string]pnpmImporter{".": l.pnpmImporter}
	}
	importerVersion := func(v any) string {
		switch t := v.(type) {
		case string:
			return t
		case map[string]any:
			if s, ok := t["version"].(string); ok {
				return s
			}
		}
		return ""
	}
	for _, imp := range importers {
		for _, set := range []struct {
			deps map[string]any
			dev  bool
		}{{imp.Dependencies, false}, {imp.OptionalDependencies, false}, {imp.DevDependencies, true}} {
			for n, v := range set.deps {
				if k, ok := ref(n, importerVersion(v)); ok {
					g.addRoot(k, set.dev)
				}
			}
		}
	}
	return g, nil
}

// ---- PHP: composer.lock ----

func readComposerLock(lock []byte, sibling Sibling) (*Graph, error) {
	var l struct {
		Packages    []composerPkg `json:"packages"`
		PackagesDev []composerPkg `json:"packages-dev"`
	}
	if err := json.Unmarshal(lock, &l); err != nil {
		return nil, err
	}
	g := newGraph()
	byName := map[string]string{}
	devSection := map[string]bool{}
	all := append(append([]composerPkg{}, l.Packages...), l.PackagesDev...)
	for _, p := range l.PackagesDev {
		devSection[strings.ToLower(p.Name)] = true
	}
	for _, p := range all {
		byName[strings.ToLower(p.Name)] = g.addNode(p.Name, p.Version)
	}
	for _, p := range all {
		for dep := range p.Require {
			if to, ok := byName[strings.ToLower(dep)]; ok {
				g.addEdge(byName[strings.ToLower(p.Name)], to)
			}
		}
	}
	if manifest, ok := sibling("composer.json"); ok {
		var m struct {
			Require    map[string]string `json:"require"`
			RequireDev map[string]string `json:"require-dev"`
		}
		if err := json.Unmarshal(manifest, &m); err == nil {
			for n := range m.Require {
				if k, ok := byName[strings.ToLower(n)]; ok {
					g.addRoot(k, false)
				}
			}
			for n := range m.RequireDev {
				if k, ok := byName[strings.ToLower(n)]; ok {
					g.addRoot(k, true)
				}
			}
			return g, nil
		}
	}
	// No manifest: packages nothing requires are roots, development when listed under packages-dev.
	g.inferRoots()
	for i, r := range g.Roots {
		g.Roots[i].Dev = devSection[strings.ToLower(g.Nodes[r.Key].Name)]
	}
	return g, nil
}

type composerPkg struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Require map[string]string `json:"require"`
}

// ---- Python: poetry.lock, uv.lock, Pipfile.lock ----

var pyReqNameRe = regexp.MustCompile(`^\s*([A-Za-z0-9][A-Za-z0-9._-]*)`)

func readPoetryLock(lock []byte, sibling Sibling) (*Graph, error) {
	var l struct {
		Package []struct {
			Name         string         `toml:"name"`
			Version      string         `toml:"version"`
			Dependencies map[string]any `toml:"dependencies"`
		} `toml:"package"`
	}
	if _, err := toml.Decode(string(lock), &l); err != nil {
		return nil, err
	}
	g := newGraph()
	g.NormalizeName = NormalizePyPI
	byName := map[string]string{}
	for _, p := range l.Package {
		byName[NormalizePyPI(p.Name)] = g.addNode(p.Name, p.Version)
	}
	for _, p := range l.Package {
		for dep := range p.Dependencies {
			if to, ok := byName[NormalizePyPI(dep)]; ok {
				g.addEdge(byName[NormalizePyPI(p.Name)], to)
			}
		}
	}
	if !pyprojectRoots(g, byName, sibling) {
		g.inferRoots()
	}
	return g, nil
}

// pyprojectRoots reads direct dependencies and their groups from pyproject.toml: Poetry's tables,
// PEP 621 [project] and PEP 735 [dependency-groups].
func pyprojectRoots(g *Graph, byName map[string]string, sibling Sibling) bool {
	raw, ok := sibling("pyproject.toml")
	if !ok {
		return false
	}
	var p struct {
		Project struct {
			Dependencies         []string            `toml:"dependencies"`
			OptionalDependencies map[string][]string `toml:"optional-dependencies"`
		} `toml:"project"`
		DependencyGroups map[string][]any `toml:"dependency-groups"`
		Tool             struct {
			Poetry struct {
				Dependencies    map[string]any `toml:"dependencies"`
				DevDependencies map[string]any `toml:"dev-dependencies"`
				Group           map[string]struct {
					Dependencies map[string]any `toml:"dependencies"`
				} `toml:"group"`
			} `toml:"poetry"`
			Uv struct {
				DevDependencies []string `toml:"dev-dependencies"`
			} `toml:"uv"`
		} `toml:"tool"`
	}
	if _, err := toml.Decode(string(raw), &p); err != nil {
		return false
	}
	add := func(name string, dev bool) {
		if k, ok := byName[NormalizePyPI(name)]; ok {
			g.addRoot(k, dev)
		}
	}
	fromReq := func(req string) string {
		if m := pyReqNameRe.FindStringSubmatch(req); m != nil {
			return m[1]
		}
		return ""
	}
	for _, r := range p.Project.Dependencies {
		add(fromReq(r), false)
	}
	for _, reqs := range p.Project.OptionalDependencies {
		for _, r := range reqs {
			add(fromReq(r), false)
		}
	}
	for _, reqs := range p.DependencyGroups {
		for _, r := range reqs {
			if s, ok := r.(string); ok {
				add(fromReq(s), true)
			}
		}
	}
	for _, r := range p.Tool.Uv.DevDependencies {
		add(fromReq(r), true)
	}
	for n := range p.Tool.Poetry.Dependencies {
		add(n, false)
	}
	for n := range p.Tool.Poetry.DevDependencies {
		add(n, true)
	}
	for group, gr := range p.Tool.Poetry.Group {
		for n := range gr.Dependencies {
			add(n, group != "main")
		}
	}
	return true
}

func readUvLock(lock []byte, _ Sibling) (*Graph, error) {
	type uvDep struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
	}
	var l struct {
		Package []struct {
			Name                 string             `toml:"name"`
			Version              string             `toml:"version"`
			Source               map[string]any     `toml:"source"`
			Dependencies         []uvDep            `toml:"dependencies"`
			OptionalDependencies map[string][]uvDep `toml:"optional-dependencies"`
			DevDependencies      map[string][]uvDep `toml:"dev-dependencies"`
		} `toml:"package"`
	}
	if _, err := toml.Decode(string(lock), &l); err != nil {
		return nil, err
	}
	g := newGraph()
	g.NormalizeName = NormalizePyPI
	byName := map[string][]string{}
	keyOfPkg := make([]string, len(l.Package))
	local := map[int]bool{}
	for i, p := range l.Package {
		if _, editable := p.Source["editable"]; editable {
			local[i] = true
		}
		if _, virtual := p.Source["virtual"]; virtual {
			local[i] = true
		}
		if local[i] {
			continue
		}
		keyOfPkg[i] = g.addNode(p.Name, p.Version)
		n := NormalizePyPI(p.Name)
		byName[n] = append(byName[n], keyOfPkg[i])
	}
	find := func(d uvDep) (string, bool) {
		ks := byName[NormalizePyPI(d.Name)]
		if d.Version != "" {
			for _, k := range ks {
				if g.Nodes[k].Version == d.Version {
					return k, true
				}
			}
		}
		if len(ks) >= 1 {
			return ks[0], true
		}
		return "", false
	}
	for i, p := range l.Package {
		var all []uvDep
		all = append(all, p.Dependencies...)
		for _, ds := range p.OptionalDependencies {
			all = append(all, ds...)
		}
		if local[i] {
			for _, d := range all {
				if k, ok := find(d); ok {
					g.addRoot(k, false)
				}
			}
			for _, ds := range p.DevDependencies {
				for _, d := range ds {
					if k, ok := find(d); ok {
						g.addRoot(k, true)
					}
				}
			}
			continue
		}
		for _, d := range all {
			if to, ok := find(d); ok {
				g.addEdge(keyOfPkg[i], to)
			}
		}
	}
	if len(local) == 0 {
		g.inferRoots()
	}
	return g, nil
}

func readPipfileLock(lock []byte, sibling Sibling) (*Graph, error) {
	var l struct {
		Default map[string]any `json:"default"`
		Develop map[string]any `json:"develop"`
	}
	if err := json.Unmarshal(lock, &l); err != nil {
		return nil, err
	}
	g := &Graph{EdgesRecorded: false, Relations: map[string]string{}, NormalizeName: NormalizePyPI}
	raw, ok := sibling("Pipfile")
	if !ok {
		return g, nil
	}
	var pf struct {
		Packages    map[string]any `toml:"packages"`
		DevPackages map[string]any `toml:"dev-packages"`
	}
	if _, err := toml.Decode(string(raw), &pf); err != nil {
		return g, nil
	}
	direct := map[string]bool{}
	for n := range pf.Packages {
		direct[NormalizePyPI(n)] = true
	}
	for n := range pf.DevPackages {
		direct[NormalizePyPI(n)] = true
	}
	for _, section := range []map[string]any{l.Default, l.Develop} {
		for n := range section {
			rel := "transitive"
			if direct[NormalizePyPI(n)] {
				rel = "direct"
			}
			g.Relations[NormalizePyPI(n)] = rel
		}
	}
	return g, nil
}

// ---- Rust: Cargo.lock ----

func readCargoLock(lock []byte, sibling Sibling) (*Graph, error) {
	var l struct {
		Package []struct {
			Name         string   `toml:"name"`
			Version      string   `toml:"version"`
			Source       string   `toml:"source"`
			Dependencies []string `toml:"dependencies"`
		} `toml:"package"`
	}
	if _, err := toml.Decode(string(lock), &l); err != nil {
		return nil, err
	}
	g := newGraph()
	byName := map[string][]string{}
	local := map[int]bool{}
	for i, p := range l.Package {
		if p.Source == "" {
			local[i] = true
			continue
		}
		k := g.addNode(p.Name, p.Version)
		byName[p.Name] = append(byName[p.Name], k)
	}
	find := func(dep string) (string, bool) {
		fields := strings.Fields(dep)
		ks := byName[fields[0]]
		if len(fields) > 1 {
			for _, k := range ks {
				if g.Nodes[k].Version == fields[1] {
					return k, true
				}
			}
		}
		if len(ks) == 1 {
			return ks[0], true
		}
		return "", false
	}
	devNames := map[string]bool{}
	if raw, ok := sibling("Cargo.toml"); ok {
		var m struct {
			Dependencies    map[string]any `toml:"dependencies"`
			DevDependencies map[string]any `toml:"dev-dependencies"`
		}
		if _, err := toml.Decode(string(raw), &m); err == nil {
			for n := range m.DevDependencies {
				if _, alsoProd := m.Dependencies[n]; !alsoProd {
					devNames[n] = true
				}
			}
		}
	} else {
		g.RootsKnown = false
	}
	for i, p := range l.Package {
		for _, d := range p.Dependencies {
			to, ok := find(d)
			if !ok {
				continue
			}
			if local[i] {
				g.addRoot(to, devNames[strings.Fields(d)[0]])
			} else {
				g.addEdge(Node{Name: p.Name, Version: p.Version}.Key(), to)
			}
		}
	}
	return g, nil
}

// ---- .NET: packages.lock.json ----

func readNugetLock(lock []byte, _ Sibling) (*Graph, error) {
	var l struct {
		Dependencies map[string]map[string]struct {
			Type         string            `json:"type"`
			Resolved     string            `json:"resolved"`
			Dependencies map[string]string `json:"dependencies"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(lock, &l); err != nil {
		return nil, err
	}
	g := newGraph()
	// NuGet has no development group: every package ships.
	g.RootsKnown = false
	frameworks := make([]string, 0, len(l.Dependencies))
	for fw := range l.Dependencies {
		frameworks = append(frameworks, fw)
	}
	sort.Strings(frameworks)
	for _, fw := range frameworks {
		pkgs := l.Dependencies[fw]
		byName := map[string]string{}
		for n, p := range pkgs {
			if p.Type == "Project" {
				continue
			}
			byName[strings.ToLower(n)] = g.addNode(n, p.Resolved)
		}
		for n, p := range pkgs {
			from, ok := byName[strings.ToLower(n)]
			if !ok {
				continue
			}
			if p.Type == "Direct" {
				g.addRoot(from, false)
			}
			for d := range p.Dependencies {
				if to, ok := byName[strings.ToLower(d)]; ok {
					g.addEdge(from, to)
				}
			}
		}
	}
	return g, nil
}

// ---- Files that say direct or transitive, but record no edges ----

var goRequireRe = regexp.MustCompile(`^\s*(?:require\s+)?([^\s()]+)\s+(v[^\s]+)(\s*//\s*indirect)?`)

func readGoMod(lock []byte, _ Sibling) (*Graph, error) {
	g := &Graph{EdgesRecorded: false, Relations: map[string]string{}}
	inRequire := false
	sc := bufio.NewScanner(strings.NewReader(string(lock)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "require ("):
			inRequire = true
			continue
		case inRequire && line == ")":
			inRequire = false
			continue
		case !inRequire && !strings.HasPrefix(line, "require "):
			continue
		}
		if m := goRequireRe.FindStringSubmatch(line); m != nil {
			rel := "direct"
			if m[3] != "" {
				rel = "transitive"
			}
			g.Relations[m[1]] = rel
		}
	}
	return g, nil
}

func readPubspecLock(lock []byte, _ Sibling) (*Graph, error) {
	var l struct {
		Packages map[string]struct {
			Dependency string `yaml:"dependency"`
		} `yaml:"packages"`
	}
	if err := yaml.Unmarshal(lock, &l); err != nil {
		return nil, err
	}
	g := &Graph{EdgesRecorded: false, Relations: map[string]string{}, DevNames: map[string]bool{}}
	for n, p := range l.Packages {
		switch {
		case strings.HasPrefix(p.Dependency, "direct"):
			g.Relations[n] = "direct"
			if p.Dependency == "direct dev" {
				g.DevNames[n] = true
			}
		case p.Dependency == "transitive":
			g.Relations[n] = "transitive"
		}
	}
	return g, nil
}

// readGradleLock reads which configurations each artifact is locked for. An artifact locked only
// for test configurations (testCompileClasspath, testRuntimeClasspath and the like) is development.
// Gradle's lockfile records no edges and no direct or transitive relation.
func readGradleLock(lock []byte, _ Sibling) (*Graph, error) {
	g := &Graph{EdgesRecorded: false, Relations: map[string]string{}, DevNames: map[string]bool{}}
	sc := bufio.NewScanner(strings.NewReader(string(lock)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty=") {
			continue
		}
		coord, configs, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		parts := strings.Split(coord, ":")
		if len(parts) < 3 {
			continue
		}
		name := parts[0] + ":" + parts[1]
		testOnly := configs != ""
		for _, c := range strings.Split(configs, ",") {
			if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(c)), "test") {
				testOnly = false
			}
		}
		if testOnly {
			g.DevNames[name] = true
		}
	}
	return g, nil
}

// readDirectOnly is for manifests that list only the part's own direct dependencies (pom.xml).
func readDirectOnly(_ []byte, _ Sibling) (*Graph, error) {
	return &Graph{EdgesRecorded: false, Relations: map[string]string{"*": "direct"}}, nil
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
