package inventory

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/kimathinjoki/depwatch-cli/schema"
)

func sample() *Inventory {
	return &Inventory{
		SchemaVersion: SchemaVersion, CLIVersion: "1.2.3", TakenAt: "2026-11-12T10:00:00Z", TakenBy: "cli",
		Part: Part{Root: "prospec360", Commit: "abc", Branch: "main", ProductionBranch: "main"},
		Packages: []Package{{Ecosystem: "RubyGems", Name: "rack", Version: "2.2.3", PURL: "pkg:gem/rack@2.2.3",
			Scope: ScopeProduction, ScopeRecorded: true, Relation: RelationTransitive, SourceFile: "api/Gemfile.lock",
			Paths: [][]Step{{{Name: "rails", Version: "7.0.4"}, {Name: "rack", Version: "2.2.3"}}}, MorePaths: 2, PathsRecorded: true}},
		OSPackages:   []OSPackage{{Distribution: "Debian", Release: "12", Ecosystem: "Debian:12", Name: "liblzma5", Version: "5.4.1-0.2", SourceName: "xz-utils", SourceVersion: "5.4.1-0.2", SourceFile: "var/lib/dpkg/status"}},
		Runtimes:     []Runtime{{Kind: KindRuntime, Name: "ruby", Version: "3.3.4", SourceFile: ".ruby-version"}},
		Images:       []Image{{Reference: "ruby:3.3", Read: false, Reason: "not pulled"}},
		FilesRead:    []FileRead{{Path: "api/Gemfile.lock", Ecosystem: "RubyGems", Reader: "ruby/gemfilelock", Packages: 1}},
		FilesNotRead: []FileNotRead{{Path: "client/package-lock.json", Reason: "bad json"}},
		Unsupported:  []Unsupported{{Path: "build.sbt", Ecosystem: "Scala (sbt)"}},
		Unpinned:     []Unpinned{{Path: "tools/package.json", Ecosystem: "npm"}},
		Conflicts:    []Conflict{{Name: "ruby", Runtimes: []Runtime{{Kind: KindRuntime, Name: "ruby", Version: "3.3.4", SourceFile: "depwatch.yml"}}}},
	}
}

// An inventory written to JSON and read back is identical.
func TestRoundTrip(t *testing.T) {
	inv := sample()
	var buf bytes.Buffer
	if err := inv.Write(&buf); err != nil {
		t.Fatal(err)
	}
	back, err := Read(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(inv, back) {
		t.Fatalf("round trip changed the inventory:\n%+v\n%+v", inv, back)
	}
	empty := &Inventory{SchemaVersion: SchemaVersion, TakenAt: "2026-11-12T10:00:00Z", TakenBy: "cli"}
	buf.Reset()
	_ = empty.Write(&buf)
	if strings.Contains(buf.String(), "null") {
		t.Fatalf("an empty inventory must write empty lists, not null:\n%s", buf.String())
	}
}

func TestValidatesAgainstSchema(t *testing.T) {
	if err := sample().Validate(); err != nil {
		t.Fatal(err)
	}
	bad := sample()
	bad.Packages[0].Scope = "staging"
	if err := bad.Validate(); err == nil {
		t.Fatal("a scope outside production and development must fail the schema")
	}
}

func TestReadRefusesOtherVersionsAndUnknownFields(t *testing.T) {
	if _, err := Read(strings.NewReader(`{"schema_version":"0"}`)); err == nil {
		t.Fatal("an older schema version must be refused")
	}
	if _, err := Read(strings.NewReader(`{"schema_version":"1","surprise":1}`)); err == nil {
		t.Fatal("an unknown field must be refused")
	}
}

// fieldPaths lists every JSON field path of a type, for example "packages[].paths[][].name".
func fieldPaths(t reflect.Type, prefix string, out *[]string) {
	for t.Kind() == reflect.Slice || t.Kind() == reflect.Pointer {
		if t.Kind() == reflect.Slice {
			prefix += "[]"
		}
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		p := name
		if prefix != "" {
			p = prefix + "." + name
		}
		*out = append(*out, p)
		fieldPaths(f.Type, p, out)
	}
}

func schemaPaths(node map[string]any, prefix string, out *[]string) {
	if items, ok := node["items"].(map[string]any); ok {
		schemaPaths(items, prefix+"[]", out)
		return
	}
	props, _ := node["properties"].(map[string]any)
	for name, sub := range props {
		p := name
		if prefix != "" {
			p = prefix + "." + name
		}
		*out = append(*out, p)
		schemaPaths(sub.(map[string]any), p, out)
	}
}

// A field added without bumping the schema version fails: the model, the committed schema and the
// field list recorded for this schema version must all agree.
func TestFieldsMatchSchemaVersion(t *testing.T) {
	var model []string
	fieldPaths(reflect.TypeOf(Inventory{}), "", &model)
	sort.Strings(model)

	var doc map[string]any
	if err := json.Unmarshal(schema.Inventory, &doc); err != nil {
		t.Fatal(err)
	}
	var fromSchema []string
	schemaPaths(doc, "", &fromSchema)
	sort.Strings(fromSchema)
	if !reflect.DeepEqual(model, fromSchema) {
		t.Fatalf("the model and schema/inventory.schema.json differ.\nmodel:  %v\nschema: %v", model, fromSchema)
	}

	golden := "testdata/fields_v" + SchemaVersion + ".txt"
	want, err := os.ReadFile(golden)
	if os.Getenv("DEPWATCH_WRITE_FIELDS") == "1" {
		_ = os.WriteFile(golden, []byte(strings.Join(model, "\n")+"\n"), 0o644)
		return
	}
	if err != nil {
		t.Fatalf("no field list for schema version %s (%v). A new version needs %s.", SchemaVersion, err, golden)
	}
	if strings.TrimSpace(string(want)) != strings.Join(model, "\n") {
		t.Fatalf("the inventory's fields changed but SchemaVersion is still %q. Bump SchemaVersion, update "+
			"schema/inventory.schema.json, and record the new field list in testdata/fields_v<version>.txt "+
			"(DEPWATCH_WRITE_FIELDS=1 go test ./internal/inventory).", SchemaVersion)
	}
}
