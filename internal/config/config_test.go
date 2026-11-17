package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"

	"github.com/kimathinjoki/watchdep-cli/internal/inventory"
	"github.com/kimathinjoki/watchdep-cli/schema"
)

// .ruby-version, .nvmrc, .python-version and .tool-versions each add a runtime with its source file.
func TestVersionFiles(t *testing.T) {
	cases := []struct {
		file, content, name, version string
	}{
		{"api/.ruby-version", "ruby-3.3.4\n", "ruby", "3.3.4"},
		{"client/.nvmrc", "v20.11.1\n", "node", "20.11.1"},
		{".node-version", "18.19.0", "node", "18.19.0"},
		{"ml/.python-version", "3.12.1\n", "python", "3.12.1"},
	}
	for _, c := range cases {
		rs := ReadVersionFile(c.file, []byte(c.content))
		if len(rs) != 1 || rs[0].Name != c.name || rs[0].Version != c.version || rs[0].SourceFile != c.file {
			t.Errorf("%s: %+v", c.file, rs)
		}
	}
	rs := ReadVersionFile(".tool-versions", []byte("ruby 3.3.4\nnodejs 20.11.1 # comment\npostgres 16.2\n"))
	if len(rs) != 3 || rs[1].Name != "node" || rs[2].Kind != inventory.KindDatabase || rs[2].Name != "postgres" {
		t.Fatalf(".tool-versions: %+v", rs)
	}
	if rs := ReadVersionFile(".nvmrc", []byte("lts/*\n")); rs[0].Version != "lts/*" {
		t.Fatalf("a moving alias is listed as written, never resolved: %+v", rs)
	}
}

// When watchdep.yml and a version file disagree, both are listed and the conflict is reported.
func TestConflicts(t *testing.T) {
	cfg, err := Parse(strings.NewReader("runtimes:\n  ruby: \"3.3.4\"\n"), FileName)
	if err != nil {
		t.Fatal(err)
	}
	fromFiles := ReadVersionFile("api/.ruby-version", []byte("3.2.2"))
	cs := Conflicts(cfg.FromConfig(), fromFiles)
	if len(cs) != 1 || cs[0].Name != "ruby" || len(cs[0].Runtimes) != 2 {
		t.Fatalf("conflicts: %+v", cs)
	}
	if cs := Conflicts(cfg.FromConfig(), ReadVersionFile(".ruby-version", []byte("3.3.4"))); len(cs) != 0 {
		t.Fatalf("agreeing sources are not a conflict: %+v", cs)
	}
	// Two folders of a monorepo may run different versions.
	two := append(ReadVersionFile("a/.nvmrc", []byte("18")), ReadVersionFile("b/.nvmrc", []byte("20"))...)
	if cs := Conflicts(nil, two); len(cs) != 0 {
		t.Fatalf("different folders are not compared: %+v", cs)
	}
}

// An unknown key or a wrong type in watchdep.yml stops the run and names the line.
func TestBadConfigNamesTheLine(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{"production_branch: main\nruntime:\n  ruby: 3.3\n", "line 2"},
		{"databases:\n  - engine: postgres\n    version: [16]\n", "line 3"},
		{"ignore: docs\n", "line 1"},
		{"images:\n  - ruby:3.3\n  - {a: b}\n", "line 3"},
	} {
		_, err := Parse(strings.NewReader(c.src), FileName)
		var ce *Error
		if !errors.As(err, &ce) {
			t.Errorf("%q: want a config error, got %v", c.src, err)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: %v does not name %s", c.src, err, c.want)
		}
	}
}

func TestVersionsKeepTheirText(t *testing.T) {
	cfg, err := Parse(strings.NewReader("runtimes:\n  python: 3.10\ndatabases:\n  - engine: Postgres\n    version: 16\n"), FileName)
	if err != nil {
		t.Fatal(err)
	}
	rs := cfg.FromConfig()
	if rs[0].Version != "3.10" || rs[1].Name != "postgres" || rs[1].Version != "16" {
		t.Fatalf("%+v", rs)
	}
}

// The annotated example validates against the committed schema, and every key the reader accepts is
// in the schema.
func TestExampleAndSchemaAgree(t *testing.T) {
	raw, err := os.ReadFile("../../examples/watchdep.yml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Parse(bytes.NewReader(raw), "examples/watchdep.yml"); err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	asJSON, _ := json.Marshal(doc)
	sdoc, _ := jsonschema.UnmarshalJSON(bytes.NewReader(schema.Config))
	c := jsonschema.NewCompiler()
	if err := c.AddResource("watchdep.schema.json", sdoc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile("watchdep.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	inst, _ := jsonschema.UnmarshalJSON(bytes.NewReader(asJSON))
	if err := s.Validate(inst); err != nil {
		t.Fatalf("the example does not validate: %v", err)
	}
	var sm struct {
		Properties map[string]any `json:"properties"`
	}
	_ = json.Unmarshal(schema.Config, &sm)
	var schemaKeys []string
	for k := range sm.Properties {
		schemaKeys = append(schemaKeys, k)
	}
	sort.Strings(schemaKeys)
	want := []string{"databases", "hosting", "ignore", "images", "production_branch", "runtimes", "version"}
	if strings.Join(schemaKeys, ",") != strings.Join(want, ",") {
		t.Fatalf("schema keys %v, reader keys %v", schemaKeys, want)
	}
}

func TestMissingFileIsEmpty(t *testing.T) {
	c, err := Load(t.TempDir())
	if err != nil || c.Path != "" {
		t.Fatalf("%+v %v", c, err)
	}
}
