package graph

import (
	"os"
	"strings"
	"testing"
	"time"
)

func names(p []Node) string {
	var s []string
	for _, n := range p {
		s = append(s, n.Name)
	}
	return strings.Join(s, " > ")
}

func pathSet(info Info) map[string]bool {
	out := map[string]bool{}
	for _, p := range info.Paths {
		out[names(p)] = true
	}
	return out
}

func noSibling(string) ([]byte, bool) { return nil, false }

func siblings(files map[string]string) Sibling {
	return func(name string) ([]byte, bool) {
		s, ok := files[name]
		return []byte(s), ok
	}
}

func resolveFile(t *testing.T, file string, lock string, sib Sibling) (*Graph, map[string]Info) {
	t.Helper()
	g, err := Read(file, []byte(lock), sib)
	if err != nil {
		t.Fatal(err)
	}
	return g, g.Resolve()
}

func info(t *testing.T, g *Graph, infos map[string]Info, name, version string) Info {
	t.Helper()
	k, ok := g.Lookup(name, version)
	if !ok {
		t.Fatalf("%s %s not in the graph", name, version)
	}
	return infos[k]
}

// In a fixture Gemfile.lock, rack reached through rails and through sidekiq has both paths.
func TestGemfileLockPaths(t *testing.T) {
	lock, _ := os.ReadFile("../../testdata/fixtures/monorepo/api/Gemfile.lock")
	gemfile, _ := os.ReadFile("../../testdata/fixtures/monorepo/api/Gemfile")
	g, infos := resolveFile(t, "api/Gemfile.lock", string(lock), siblings(map[string]string{"Gemfile": string(gemfile)}))
	rack := info(t, g, infos, "rack", "2.2.3")
	ps := pathSet(rack)
	if !ps["sidekiq > rack"] || !ps["rails > actionpack > rack"] {
		t.Fatalf("rack's paths: %v", ps)
	}
	// A package reached by more than five paths keeps the five shortest and a count of the rest.
	if len(rack.Paths) != MaxPaths || rack.MorePaths != 6 {
		t.Fatalf("rack keeps %d paths and counts %d more; want 5 and 6", len(rack.Paths), rack.MorePaths)
	}
	for i := 1; i < len(rack.Paths); i++ {
		if len(rack.Paths[i]) < len(rack.Paths[i-1]) {
			t.Fatalf("paths are not shortest first: %v", ps)
		}
	}
	// Reached only from development groups: development. Reached from both: production.
	if s := info(t, g, infos, "bindex", "0.8.1").Scope; s != "development" {
		t.Errorf("bindex is only under web-console (development): got %s", s)
	}
	if s := info(t, g, infos, "actionpack", "7.0.4").Scope; s != "production" {
		t.Errorf("actionpack is under rails and rspec-rails: got %s", s)
	}
	if r := info(t, g, infos, "rails", "7.0.4").Relation; r != "direct" {
		t.Errorf("rails is direct: got %s", r)
	}
}

func TestWithoutGemfileScopeIsNotKnown(t *testing.T) {
	lock, _ := os.ReadFile("../../testdata/fixtures/monorepo/api/Gemfile.lock")
	g, _ := resolveFile(t, "Gemfile.lock", string(lock), noSibling)
	if g.RootsKnown {
		t.Fatal("without the Gemfile, groups are not known")
	}
}

// A cycle in a lockfile's edges does not hang or duplicate a path.
func TestCycle(t *testing.T) {
	g := newGraph()
	a, b, c := g.addNode("a", "1"), g.addNode("b", "1"), g.addNode("c", "1")
	g.addEdge(a, b)
	g.addEdge(b, c)
	g.addEdge(c, a)
	g.addEdge(c, b)
	g.addRoot(a, false)
	done := make(chan map[string]Info)
	go func() { done <- g.Resolve() }()
	select {
	case infos := <-done:
		ic := infos[c]
		if len(ic.Paths) != 1 || names(ic.Paths[0]) != "a > b > c" || ic.MorePaths != 0 {
			t.Fatalf("c: %+v", ic)
		}
		seen := map[string]bool{}
		for _, in := range infos {
			for _, p := range in.Paths {
				if seen[names(p)] {
					t.Fatalf("duplicate path %s", names(p))
				}
				seen[names(p)] = true
			}
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a cycle hung the resolver")
	}
}

// A dense graph keeps five paths and counts the rest without enumerating them.
func TestManyPaths(t *testing.T) {
	g := newGraph()
	target := g.addNode("target", "1")
	prev := []string{}
	for layer := 0; layer < 12; layer++ {
		var cur []string
		for i := 0; i < 3; i++ {
			k := g.addNode(string(rune('a'+layer))+string(rune('0'+i)), "1")
			cur = append(cur, k)
			for _, p := range prev {
				g.addEdge(p, k)
			}
			if layer == 0 {
				g.addRoot(k, false)
			}
		}
		prev = cur
	}
	for _, p := range prev {
		g.addEdge(p, target)
	}
	in := g.Resolve()[target]
	if len(in.Paths) != MaxPaths {
		t.Fatalf("kept %d paths", len(in.Paths))
	}
	if in.MorePaths < 100000 {
		t.Fatalf("expected a very large count, got %d", in.MorePaths)
	}
}

// In an ecosystem whose lockfile records no edges, the package is marked direct or transitive where
// the file says so, and has no paths.
func TestGoModRelationsWithoutEdges(t *testing.T) {
	g, err := Read("go.mod", []byte("module x\n\ngo 1.22\n\nrequire (\n\tgithub.com/a/b v1.2.3\n\tgithub.com/c/d v0.1.0 // indirect\n)\n\nrequire golang.org/x/net v0.20.0\n"), noSibling)
	if err != nil {
		t.Fatal(err)
	}
	if g.EdgesRecorded {
		t.Fatal("go.mod records no edges")
	}
	if g.Relations["github.com/a/b"] != "direct" || g.Relations["github.com/c/d"] != "transitive" || g.Relations["golang.org/x/net"] != "direct" {
		t.Fatalf("relations: %v", g.Relations)
	}
	if len(g.Resolve()) != 0 {
		t.Fatal("no paths without edges")
	}
}

func TestPackageLockV3(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{
	  "":{"dependencies":{"a":"^1"},"devDependencies":{"d":"^1"}},
	  "node_modules/a":{"version":"1.0.0","dependencies":{"b":"^1"}},
	  "node_modules/b":{"version":"1.0.0"},
	  "node_modules/a/node_modules/b":{"version":"2.0.0","dependencies":{"c":"*"}},
	  "node_modules/c":{"version":"3.0.0"},
	  "node_modules/d":{"version":"1.0.0","dev":true,"dependencies":{"b":"^1"}}}}`
	g, infos := resolveFile(t, "package-lock.json", lock, noSibling)
	b2 := info(t, g, infos, "b", "2.0.0")
	if names(b2.Paths[0]) != "a > b" || b2.Scope != "production" {
		t.Fatalf("nested b@2 must resolve under a: %+v", b2)
	}
	b1 := info(t, g, infos, "b", "1.0.0")
	if b1.Scope != "development" || names(b1.Paths[0]) != "d > b" {
		t.Fatalf("b@1 is reached only from the dev dependency d: %+v", b1)
	}
	if c := info(t, g, infos, "c", "3.0.0"); names(c.Paths[0]) != "a > b > c" {
		t.Fatalf("c: %+v", c)
	}
}

func TestPackageLockV1(t *testing.T) {
	lock := `{"lockfileVersion":1,"dependencies":{
	  "event-stream":{"version":"3.3.6","requires":{"flatmap-stream":"0.1.1"}},
	  "flatmap-stream":{"version":"0.1.1"},
	  "mocha":{"version":"5.0.0","dev":true}}}`
	g, infos := resolveFile(t, "package-lock.json", lock, noSibling)
	fs := info(t, g, infos, "flatmap-stream", "0.1.1")
	if names(fs.Paths[0]) != "event-stream > flatmap-stream" || fs.Scope != "production" {
		t.Fatalf("flatmap-stream: %+v", fs)
	}
	if m := info(t, g, infos, "mocha", "5.0.0"); m.Scope != "development" {
		t.Fatalf("mocha: %+v", m)
	}
}

func TestYarnClassic(t *testing.T) {
	lock := `# yarn lockfile v1

"@scope/a@^1.0.0":
  version "1.2.0"
  dependencies:
    ua-parser-js "^0.7.0"

ua-parser-js@^0.7.0, ua-parser-js@^0.7.28:
  version "0.7.29"

jest@^29:
  version "29.0.0"
  dependencies:
    ua-parser-js "^0.7.28"
`
	pkg := `{"dependencies":{"@scope/a":"^1.0.0"},"devDependencies":{"jest":"^29"}}`
	g, infos := resolveFile(t, "yarn.lock", lock, siblings(map[string]string{"package.json": pkg}))
	ua := info(t, g, infos, "ua-parser-js", "0.7.29")
	ps := pathSet(ua)
	if !ps["@scope/a > ua-parser-js"] || !ps["jest > ua-parser-js"] || ua.Scope != "production" {
		t.Fatalf("ua-parser-js: %+v", ua)
	}
}

func TestYarnBerry(t *testing.T) {
	lock := `__metadata:
  version: 6

"app@workspace:.":
  version: 0.0.0-use.local
  dependencies:
    left-pad: "npm:^1.3.0"

"left-pad@npm:^1.3.0":
  version: 1.3.0
  dependencies:
    tiny: "npm:1.0.0"

"tiny@npm:1.0.0":
  version: 1.0.0
`
	g, infos := resolveFile(t, "yarn.lock", lock, siblings(map[string]string{"package.json": `{"dependencies":{"left-pad":"^1.3.0"}}`}))
	if p := info(t, g, infos, "tiny", "1.0.0"); names(p.Paths[0]) != "left-pad > tiny" {
		t.Fatalf("tiny: %+v", p)
	}
}

func TestPnpmV9(t *testing.T) {
	lock := `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      express:
        specifier: ^4.18.0
        version: 4.18.2
    devDependencies:
      vitest:
        specifier: ^1.0.0
        version: 1.0.0(@types/node@20.0.0)
packages:
  express@4.18.2:
    resolution: {integrity: x}
  body-parser@1.20.1:
    resolution: {integrity: x}
  vitest@1.0.0:
    resolution: {integrity: x}
snapshots:
  express@4.18.2:
    dependencies:
      body-parser: 1.20.1
  body-parser@1.20.1: {}
  vitest@1.0.0(@types/node@20.0.0):
    dependencies:
      body-parser: 1.20.1
`
	g, infos := resolveFile(t, "pnpm-lock.yaml", lock, noSibling)
	bp := info(t, g, infos, "body-parser", "1.20.1")
	if bp.Scope != "production" || !pathSet(bp)["express > body-parser"] || !pathSet(bp)["vitest > body-parser"] {
		t.Fatalf("body-parser: %+v", bp)
	}
	if v := info(t, g, infos, "vitest", "1.0.0"); v.Scope != "development" {
		t.Fatalf("vitest: %+v", v)
	}
}

func TestComposerLock(t *testing.T) {
	lock := `{"packages":[{"name":"laravel/framework","version":"v10.0.0","require":{"symfony/http-foundation":"^6.2"}},{"name":"symfony/http-foundation","version":"v6.2.0"}],
	"packages-dev":[{"name":"phpunit/phpunit","version":"10.0.0"}]}`
	g, infos := resolveFile(t, "composer.lock", lock, siblings(map[string]string{"composer.json": `{"require":{"laravel/framework":"^10"},"require-dev":{"phpunit/phpunit":"^10"}}`}))
	if s := info(t, g, infos, "symfony/http-foundation", "v6.2.0"); names(s.Paths[0]) != "laravel/framework > symfony/http-foundation" {
		t.Fatalf("http-foundation: %+v", s)
	}
	if p := info(t, g, infos, "phpunit/phpunit", "10.0.0"); p.Scope != "development" {
		t.Fatalf("phpunit: %+v", p)
	}
}

func TestPoetryLock(t *testing.T) {
	lock := `[[package]]
name = "Django"
version = "4.2.0"
[package.dependencies]
sqlparse = ">=0.3.1"

[[package]]
name = "sqlparse"
version = "0.4.3"

[[package]]
name = "pytest"
version = "7.0.0"
`
	pyproject := `[tool.poetry.dependencies]
python = "^3.11"
django = "^4.2"
[tool.poetry.group.dev.dependencies]
pytest = "^7"
`
	g, infos := resolveFile(t, "poetry.lock", lock, siblings(map[string]string{"pyproject.toml": pyproject}))
	if s := info(t, g, infos, "sqlparse", "0.4.3"); names(s.Paths[0]) != "Django > sqlparse" || s.Scope != "production" {
		t.Fatalf("sqlparse: %+v", s)
	}
	if p := info(t, g, infos, "pytest", "7.0.0"); p.Scope != "development" {
		t.Fatalf("pytest: %+v", p)
	}
}

func TestUvLock(t *testing.T) {
	lock := `version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "fastapi" }]
[package.dev-dependencies]
dev = [{ name = "pytest" }]

[[package]]
name = "fastapi"
version = "0.100.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "starlette" }]

[[package]]
name = "starlette"
version = "0.27.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "8.0.0"
source = { registry = "https://pypi.org/simple" }
`
	g, infos := resolveFile(t, "uv.lock", lock, noSibling)
	if s := info(t, g, infos, "starlette", "0.27.0"); names(s.Paths[0]) != "fastapi > starlette" || s.Scope != "production" {
		t.Fatalf("starlette: %+v", s)
	}
	if p := info(t, g, infos, "pytest", "8.0.0"); p.Scope != "development" {
		t.Fatalf("pytest: %+v", p)
	}
}

func TestCargoLock(t *testing.T) {
	lock := `version = 3
[[package]]
name = "app"
version = "0.1.0"
dependencies = ["serde", "tokio 1.30.0", "criterion"]

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.30.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
dependencies = ["mio"]

[[package]]
name = "mio"
version = "0.8.0"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "criterion"
version = "0.5.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
`
	cargo := "[package]\nname = \"app\"\n[dependencies]\nserde = \"1\"\ntokio = \"1\"\n[dev-dependencies]\ncriterion = \"0.5\"\n"
	g, infos := resolveFile(t, "Cargo.lock", lock, siblings(map[string]string{"Cargo.toml": cargo}))
	if m := info(t, g, infos, "mio", "0.8.0"); names(m.Paths[0]) != "tokio > mio" || m.Scope != "production" {
		t.Fatalf("mio: %+v", m)
	}
	if c := info(t, g, infos, "criterion", "0.5.0"); c.Scope != "development" {
		t.Fatalf("criterion: %+v", c)
	}
}

func TestNugetLock(t *testing.T) {
	lock := `{"version":1,"dependencies":{"net8.0":{
	  "Newtonsoft.Json":{"type":"Direct","requested":"[13.0.1, )","resolved":"13.0.1","dependencies":{"System.Text":"4.0.0"}},
	  "System.Text":{"type":"Transitive","resolved":"4.0.0"}}}}`
	g, infos := resolveFile(t, "packages.lock.json", lock, noSibling)
	if s := info(t, g, infos, "System.Text", "4.0.0"); names(s.Paths[0]) != "Newtonsoft.Json > System.Text" || s.Relation != "transitive" {
		t.Fatalf("System.Text: %+v", s)
	}
}

func TestPubspecLock(t *testing.T) {
	g, err := Read("pubspec.lock", []byte("packages:\n  http:\n    dependency: \"direct main\"\n  test:\n    dependency: \"direct dev\"\n  meta:\n    dependency: transitive\n"), noSibling)
	if err != nil {
		t.Fatal(err)
	}
	if g.Relations["http"] != "direct" || g.Relations["meta"] != "transitive" || !g.DevNames["test"] {
		t.Fatalf("%+v", g)
	}
}
