package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/kimathinjoki/depwatch-cli/internal/inventory"
	"github.com/kimathinjoki/depwatch-cli/internal/sources"
	"github.com/kimathinjoki/depwatch-cli/internal/testutil"
	"github.com/kimathinjoki/depwatch-cli/internal/version"
)

func run(t *testing.T, src *sources.Recording, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	env := Env{Stdout: &out, Stderr: &errb}
	if src != nil {
		env.Sources = func() (sources.Set, error) { return src.Sources(), nil }
	} else {
		env.Sources = func() (sources.Set, error) { return (&sources.Recording{}).Sources(), nil }
	}
	code := Run(args, env)
	return code, out.String(), errb.String()
}

// depwatch version prints the version, commit and build date stamped at build time.
func TestVersion(t *testing.T) {
	version.Version, version.Commit, version.Date = "1.2.3", "abc1234", "2026-11-12"
	defer func() { version.Version, version.Commit, version.Date = "dev", "none", "unknown" }()
	code, out, _ := run(t, nil, "version")
	if code != 0 || !strings.Contains(out, "1.2.3") || !strings.Contains(out, "abc1234") || !strings.Contains(out, "2026-11-12") {
		t.Fatalf("%d %q", code, out)
	}
}

// An unknown command or flag prints help and exits with the usage code.
func TestUsageErrors(t *testing.T) {
	for _, args := range [][]string{{"frobnicate"}, {"gate", "--nope"}, {"gate", "--fail-on", "everything"}, {"inventory", "a", "b"}} {
		code, _, errOut := run(t, nil, args...)
		if code != ExitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, ExitUsage)
		}
		if !strings.Contains(errOut, "depwatch:") {
			t.Errorf("%v: no error message: %q", args, errOut)
		}
	}
	_, _, errOut := run(t, nil, "frobnicate")
	if !strings.Contains(errOut, "Usage:") {
		t.Errorf("help not printed: %q", errOut)
	}
}

// --json is accepted by every command and switches all output to JSON.
func TestJSONEverywhere(t *testing.T) {
	dir := testutil.Tree(t, map[string]string{"go.mod": "module x\n\ngo 1.22\n"})
	for _, args := range [][]string{{"version", "--json"}, {"inventory", "--json", dir}, {"gate", "--json", dir}, {"frobnicate", "--json"}} {
		_, out, _ := run(t, &sources.Recording{}, args...)
		var v any
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Errorf("%v: not JSON: %v\n%s", args, err, out)
		}
	}
}

// A bad depwatch.yml stops the run with the usage code and names the line.
func TestBadConfigIsUsage(t *testing.T) {
	dir := testutil.Tree(t, map[string]string{"depwatch.yml": "runtimez:\n  ruby: 3\n"})
	code, _, errOut := run(t, nil, "inventory", dir)
	if code != ExitUsage || !strings.Contains(errOut, "line 1") {
		t.Fatalf("%d %q", code, errOut)
	}
}

type countingTransport struct{ n atomic.Int32 }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.n.Add(1)
	return nil, errors.New("network call attempted")
}

// depwatch inventory: human output shows what was not read first; --json is the schema's shape; it
// makes no network call.
func TestInventoryCommand(t *testing.T) {
	ct := &countingTransport{}
	saved := http.DefaultTransport
	http.DefaultTransport = ct
	defer func() { http.DefaultTransport = saved }()

	dir := testutil.CopyDir(t, "../../testdata/fixtures/monorepo")
	testutil.Tree(t, nil)
	writeFile(t, filepath.Join(dir, "build.sbt"), "x")
	writeFile(t, filepath.Join(dir, "depwatch.yml"), "images:\n  - ruby:3.3.4-slim\n")

	code, out, _ := run(t, nil, "inventory", dir)
	if code != ExitIncomplete {
		t.Fatalf("exit %d, want %d (unsupported file, unpulled image)", code, ExitIncomplete)
	}
	iUnsupported := strings.Index(out, "Unsupported ecosystems")
	iImages := strings.Index(out, "Images not read")
	iPackages := strings.Index(out, "Packages")
	if iUnsupported < 0 || iImages < 0 || iPackages < 0 || iUnsupported > iPackages || iImages > iPackages {
		t.Fatalf("what was not read must come first:\n%s", out)
	}
	if !strings.Contains(out, "RubyGems") || !strings.Contains(out, "npm") {
		t.Fatalf("groups by ecosystem:\n%s", out)
	}

	_, js, _ := run(t, nil, "inventory", "--json", dir)
	if err := inventory.ValidateJSON([]byte(js)); err != nil {
		t.Fatalf("--json does not match the schema: %v", err)
	}
	if n := ct.n.Load(); n != 0 {
		t.Fatalf("depwatch inventory made %d network calls", n)
	}
}

func TestColorOnlyWhenAsked(t *testing.T) {
	dir := testutil.Tree(t, map[string]string{"build.sbt": "x"})
	_, out, _ := run(t, nil, "inventory", dir)
	if strings.Contains(out, "\x1b[") {
		t.Fatal("no colour when the output is not a terminal")
	}
	var buf bytes.Buffer
	Run([]string{"inventory", dir}, Env{Stdout: &buf, Stderr: &buf, Color: true})
	if !strings.Contains(buf.String(), "\x1b[38;5;202m") {
		t.Fatalf("deep orange expected for the unsupported list:\n%q", buf.String())
	}
	for _, banned := range []string{"38;5;3m", "38;5;11m", "38;5;214m", "38;5;220m", "33m"} {
		if strings.Contains(buf.String(), "\x1b["+banned) {
			t.Fatalf("amber or yellow used: %s", banned)
		}
	}
}
