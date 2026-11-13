package fix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kimathinjoki/depwatch-cli/internal/testutil"
)

type call struct {
	dir  string
	args []string
}

func recorder(calls *[]call, effect func(dir string, args []string)) Runner {
	return func(_ context.Context, dir, name string, args ...string) error {
		*calls = append(*calls, call{dir, append([]string{name}, args...)})
		if effect != nil {
			effect(dir, append([]string{name}, args...))
		}
		return nil
	}
}

// A pinned requirements.txt line is raised to the fix version.
func TestRequirementsPin(t *testing.T) {
	root := testutil.Tree(t, map[string]string{"app/requirements.txt": "Django==4.2.0 ; python_version >= '3.10'\nrequests==2.31.0\n"})
	ch, err := Apply(context.Background(), root, Target{Kind: "package", Ecosystem: "PyPI", Name: "django", Version: "4.2.0", Fix: "4.2.16", Relation: "unknown", SourceFile: "app/requirements.txt"}, Tools{})
	if err != nil || ch.Strategy != "direct" {
		t.Fatalf("%+v %v", ch, err)
	}
	raw, _ := os.ReadFile(filepath.Join(root, "app/requirements.txt"))
	if string(raw) != "Django==4.2.16 ; python_version >= '3.10'\nrequests==2.31.0\n" {
		t.Fatalf("%q", raw)
	}
	if err := Verify(context.Background(), root, Target{Ecosystem: "PyPI", Name: "Django", Fix: "4.2.16", SourceFile: "app/requirements.txt"}); err != nil {
		t.Fatal(err)
	}
}

// npm runs `npm install name@version` for a direct dependency and writes an override for a transitive one.
func TestNpm(t *testing.T) {
	root := testutil.Tree(t, map[string]string{"web/package.json": "{\n  \"name\": \"web\",\n  \"dependencies\": {\"express\": \"^4.0.0\"}\n}\n", "web/package-lock.json": "{}"})
	var calls []call
	tools := Tools{Run: recorder(&calls, nil)}
	if _, err := Apply(context.Background(), root, Target{Kind: "package", Name: "axios", Fix: "1.7.9", Relation: "direct", SourceFile: "web/package-lock.json"}, tools); err != nil {
		t.Fatal(err)
	}
	ch, err := Apply(context.Background(), root, Target{Kind: "package", Name: "qs", Fix: "6.11.1", Relation: "transitive", SourceFile: "web/package-lock.json"}, tools)
	if err != nil || ch.Strategy != "override" {
		t.Fatalf("%+v %v", ch, err)
	}
	if strings.Join(calls[0].args, " ") != "npm install axios@^1.7.9" || strings.Join(calls[1].args, " ") != "npm install" || !strings.HasSuffix(calls[0].dir, "web") {
		t.Fatalf("%+v", calls)
	}
	raw, _ := os.ReadFile(filepath.Join(root, "web/package.json"))
	want := `{"name":"web","dependencies":{"express":"^4.0.0"},"overrides":{"qs":"6.11.1"}}`
	if strings.Join(strings.Fields(string(raw)), "") != want {
		t.Fatalf("order or content changed: %s", raw)
	}
}

func TestOtherManagers(t *testing.T) {
	root := testutil.Tree(t, map[string]string{"Gemfile.lock": "", "go.mod": "", "Cargo.lock": "", "uv.lock": "", "package.json": "{}", "pnpm-lock.yaml": ""})
	var calls []call
	tools := Tools{Run: recorder(&calls, nil)}
	for _, tc := range []struct {
		t    Target
		want string
	}{
		{Target{Kind: "package", Name: "rack", Fix: "2.2.8", Relation: "transitive", SourceFile: "Gemfile.lock"}, "bundle update --conservative rack"},
		{Target{Kind: "package", Name: "golang.org/x/net", Fix: "0.23.0", Relation: "direct", SourceFile: "go.mod"}, "go get golang.org/x/net@v0.23.0"},
		{Target{Kind: "package", Name: "tokio", Fix: "1.38.1", SourceFile: "Cargo.lock"}, "cargo update -p tokio --precise 1.38.1"},
		{Target{Kind: "package", Name: "jinja2", Fix: "3.1.4", SourceFile: "uv.lock"}, "uv lock --upgrade-package jinja2==3.1.4"},
		{Target{Kind: "package", Name: "lodash", Fix: "4.17.21", Relation: "transitive", SourceFile: "pnpm-lock.yaml"}, "pnpm install"},
	} {
		calls = nil
		if _, err := Apply(context.Background(), root, tc.t, tools); err != nil {
			t.Fatal(err)
		}
		if strings.Join(calls[0].args, " ") != tc.want {
			t.Errorf("%s: %v", tc.t.SourceFile, calls[0].args)
		}
	}
	raw, _ := os.ReadFile(filepath.Join(root, "package.json"))
	if !strings.Contains(strings.Join(strings.Fields(string(raw)), ""), `"pnpm":{"overrides":{"lodash":"4.17.21"}}`) {
		t.Fatalf("%s", raw)
	}
	if _, err := Apply(context.Background(), root, Target{Kind: "package", SourceFile: "pom.xml"}, tools); err != ErrNoFixer {
		t.Fatalf("Maven has no fixer yet: %v", err)
	}
}

// A fixer that does not reach the fix version is undone exactly.
func TestNotReachedIsRestored(t *testing.T) {
	root := testutil.Tree(t, map[string]string{"requirements.txt": "django==4.2.0\n"})
	snap, _ := TakeSnapshot(root)
	_ = os.WriteFile(filepath.Join(root, "requirements.txt"), []byte("django==4.2.1\n"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "new.lock"), []byte("x"), 0o644)
	err := Verify(context.Background(), root, Target{Ecosystem: "PyPI", Name: "django", Fix: "4.2.16", SourceFile: "requirements.txt"})
	if err == nil || !strings.Contains(err.Error(), "below the fix") {
		t.Fatalf("%v", err)
	}
	if err := snap.Restore(root); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(root, "requirements.txt"))
	if string(raw) != "django==4.2.0\n" || exists(filepath.Join(root, "new.lock")) {
		t.Fatal("not restored")
	}
}

func TestMissingPackageManager(t *testing.T) {
	err := ExecRunner(context.Background(), t.TempDir(), "depwatch-no-such-pm")
	if err == nil || !strings.Contains(err.Error(), "is not installed here") {
		t.Fatalf("%v", err)
	}
}

func TestDockerDigest(t *testing.T) {
	old := "sha256:" + strings.Repeat("a", 64)
	newer := "sha256:" + strings.Repeat("b", 64)
	root := testutil.Tree(t, map[string]string{"Dockerfile": "FROM node:20 AS build\nFROM debian:12-slim@" + old + "\nCOPY . .\n"})
	ch, err := RefreshBaseImage(root, "debian:12-slim@"+old, func(ref string) (string, error) { return newer, nil })
	if err != nil || ch.Strategy != "digest" {
		t.Fatalf("%+v %v", ch, err)
	}
	raw, _ := os.ReadFile(filepath.Join(root, "Dockerfile"))
	if !strings.Contains(string(raw), "debian:12-slim@"+newer) || !strings.Contains(string(raw), "FROM node:20 AS build") {
		t.Fatalf("%s", raw)
	}
	if _, err := RefreshBaseImage(root, "alpine:3.20", nil); err == nil {
		t.Fatal("an image not pinned by digest needs no change")
	}
}

func TestBody(t *testing.T) {
	item := Item{PrimaryID: "CVE-2023-31047", IDs: []string{"CVE-2023-31047", "GHSA-x"}, Level: "high", Summary: "Upload bypass",
		Reason: "critical (CVSS 9.8) with EPSS 2.0%, below the threshold", Labels: []string{"exploited_now"}, URL: "https://dw/findings/1",
		Targets: []Target{{Name: "django", Version: "4.2.0", Fix: "4.2.2", SourceFile: "uv.lock", Paths: [][]string{{"django"}}}}}
	body := Body(item, "api", map[string]Change{"uv.lock|django": {"update", "uv lock --upgrade-package django==4.2.2"}})
	for _, want := range []string{"CVE-2023-31047", "high", "exploited now", "api > django", "uv lock", "never merges", "https://dw/findings/1"} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}
	if BranchName(item, "API") != "depwatch/cve-2023-31047-api" {
		t.Fatal(BranchName(item, "API"))
	}
}
