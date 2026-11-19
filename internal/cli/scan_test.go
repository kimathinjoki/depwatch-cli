package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kimathinjoki/watchdep-cli/internal/testutil"
)

func dropTakenAt(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	delete(m, "taken_at")
	return m
}

// scan posts exactly the inventory `inventory --json` would print, with the token as a bearer token.
func TestScanPostsTheInventory(t *testing.T) {
	var gotAuth string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/inventories" {
			http.NotFound(w, r)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"part":"api","application":"Storefront","inventory_id":7,"production":true,"url":"http://x/inventories/7"}`))
	}))
	defer srv.Close()
	dir := testutil.CopyDir(t, "../../testdata/fixtures/monorepo")
	var out strings.Builder
	code := Run([]string{"scan", "--server", srv.URL, dir}, Env{Stdout: &out, Stderr: &out, Getenv: func(k string) string {
		if k == "WATCHDEP_TOKEN" {
			return "wdp_secret"
		}
		return ""
	}})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if gotAuth != "Bearer wdp_secret" {
		t.Fatalf("auth %q", gotAuth)
	}
	_, inv, _ := run(t, nil, "inventory", "--json", dir)
	a, b := dropTakenAt(t, gotBody), dropTakenAt(t, []byte(inv))
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatalf("scan sent a different inventory:\n%s\n%s", ja, jb)
	}
	if !strings.Contains(out.String(), "production") || !strings.Contains(out.String(), "Storefront") {
		t.Fatalf("%s", out.String())
	}
}

// A rejected token exits with the usage code and says the token was refused; an unreachable server
// exits 2.
func TestScanErrors(t *testing.T) {
	refuse := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"token refused"}`, http.StatusUnauthorized)
	}))
	defer refuse.Close()
	dir := testutil.Tree(t, map[string]string{"go.mod": "module x\n\ngo 1.22\n"})
	env := func() Env {
		return Env{Stdout: io.Discard, Stderr: io.Discard, Getenv: func(k string) string {
			if k == "WATCHDEP_TOKEN" {
				return "t"
			}
			return ""
		}}
	}
	var errOut strings.Builder
	e := env()
	e.Stderr = &errOut
	if code := Run([]string{"scan", "--server", refuse.URL, dir}, e); code != ExitUsage || !strings.Contains(errOut.String(), "refused the token") {
		t.Fatalf("refused: exit %d %s", code, errOut.String())
	}
	if code := Run([]string{"scan", "--server", "http://127.0.0.1:1", dir}, env()); code != ExitIncomplete {
		t.Fatalf("unreachable: exit %d", code)
	}
	t.Setenv("WATCHDEP_CREDENTIALS", filepath.Join(t.TempDir(), "none.json"))
	noTok := Env{Stdout: io.Discard, Stderr: io.Discard}
	if code := Run([]string{"scan", dir}, noTok); code != ExitUsage {
		t.Fatalf("no token: exit %d", code)
	}
}

// A server that will not look now (429, the plan's scans for today are used) is not a clean result:
// scan prints the server's reason and exits 2.
func TestScanNotLookedExitsIncomplete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"not looked: the plan's scans for today are used (50 of 50 on Free)","not_looked":true}`))
	}))
	defer srv.Close()
	dir := testutil.Tree(t, map[string]string{"go.mod": "module x\n\ngo 1.22\n"})
	var errOut strings.Builder
	code := Run([]string{"scan", "--server", srv.URL, dir}, Env{Stdout: io.Discard, Stderr: &errOut, Getenv: func(k string) string {
		if k == "WATCHDEP_TOKEN" {
			return "t"
		}
		return ""
	}})
	if code != ExitIncomplete {
		t.Fatalf("exit %d, want %d: %s", code, ExitIncomplete, errOut.String())
	}
	if !strings.Contains(errOut.String(), "the plan's scans for today are used (50 of 50 on Free)") || !strings.Contains(errOut.String(), "not a clean result") {
		t.Fatalf("the server's reason is missing: %s", errOut.String())
	}
}

// The stored credentials file is created with owner-only permissions, and holds the folder's login.
func TestLoginStoresPrivately(t *testing.T) {
	p := filepath.Join(t.TempDir(), "watchdep", "credentials.json")
	t.Setenv("WATCHDEP_CREDENTIALS", p)
	dir := t.TempDir()
	if code, out, _ := run(t, nil, "login", dir, "--server", "https://dw.example.test/", "--token", "wdp_abc"); code != 0 {
		t.Fatalf("exit %d %s", code, out)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("permissions %v, want 0600", st.Mode().Perm())
	}
	raw, _ := os.ReadFile(p)
	if !strings.Contains(string(raw), `"token": "wdp_abc"`) || !strings.Contains(string(raw), `"server": "https://dw.example.test"`) {
		t.Fatalf("%s", raw)
	}
	if code, _, _ := run(t, nil, "login", dir, "--server", "not a url", "--token", "x"); code != ExitUsage {
		t.Fatalf("bad server: exit %d", code)
	}
	if code, _, _ := run(t, nil, "login", filepath.Join(dir, "missing"), "--server", "https://dw.example.test", "--token", "x"); code != ExitUsage {
		t.Fatalf("missing folder: exit %d", code)
	}
}

// Two projects on one machine keep their own tokens: each folder, and the folders inside it, use its
// own login, the nearest one wins, and a folder with none is refused rather than sent under another's.
func TestLoginPerFolder(t *testing.T) {
	t.Setenv("WATCHDEP_CREDENTIALS", filepath.Join(t.TempDir(), "credentials.json"))
	base := t.TempDir()
	a, b, other := filepath.Join(base, "a"), filepath.Join(base, "b"), filepath.Join(base, "other")
	inner := filepath.Join(a, "api")
	for _, d := range []string{filepath.Join(inner, "src"), b, other} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, l := range [][]string{{a, "wdp_a"}, {b, "wdp_b"}, {inner, "wdp_api"}} {
		if code, out, errOut := run(t, nil, "login", l[0], "--server", "https://dw.example.test", "--token", l[1]); code != 0 {
			t.Fatalf("exit %d %s %s", code, out, errOut)
		}
	}
	none := &Env{Getenv: func(string) string { return "" }}
	for folder, want := range map[string]string{a: "wdp_a", b: "wdp_b", inner: "wdp_api", filepath.Join(inner, "src"): "wdp_api"} {
		srv, tok, err := resolveServer(none, "", "", folder)
		if err != nil || srv != "https://dw.example.test" || tok != want {
			t.Fatalf("%s: %s %s %v, want %s", folder, srv, tok, err, want)
		}
	}
	if _, _, err := resolveServer(none, "", "", other); err == nil || !strings.Contains(err.Error(), "no login for ") {
		t.Fatalf("a folder with no login: %v", err)
	}
	if _, _, err := resolveServer(none, "https://elsewhere.test", "", a); err == nil {
		t.Fatal("a login for another server must not be used")
	}
	env := &Env{Getenv: func(k string) string {
		return map[string]string{"WATCHDEP_SERVER": "https://ci.test", "WATCHDEP_TOKEN": "wdp_env"}[k]
	}}
	if srv, tok, _ := resolveServer(env, "", "", a); srv != "https://ci.test" || tok != "wdp_env" {
		t.Fatalf("the environment comes before a login: %s %s", srv, tok)
	}
}

// A 0.1.0 login, one token per server, is not used: it could belong to any project.
func TestOldLoginIsNotUsed(t *testing.T) {
	p := filepath.Join(t.TempDir(), "credentials.json")
	t.Setenv("WATCHDEP_CREDENTIALS", p)
	if err := os.WriteFile(p, []byte(`{"default":"https://dw.example.test","servers":{"https://dw.example.test":"wdp_old"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := resolveServer(&Env{Getenv: func(string) string { return "" }}, "", "", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "run it again in the part's folder") {
		t.Fatalf("%v", err)
	}
	dir := t.TempDir()
	if code, _, _ := run(t, nil, "login", dir, "--server", "https://dw.example.test", "--token", "wdp_new"); code != 0 {
		t.Fatal("login")
	}
	if raw, _ := os.ReadFile(p); strings.Contains(string(raw), "wdp_old") {
		t.Fatalf("the old login is dropped on the next login: %s", raw)
	}
}

// A fake server that takes the inventory as production and answers the findings once it has been
// asked notReady times.
func scanServer(t *testing.T, notReady int, findings string) (*httptest.Server, *int) {
	t.Helper()
	asked := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/inventories":
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"part":"api","application":"Storefront","inventory_id":7,"production":true,"url":"http://x/inventories/7"}`))
		case "/api/v1/findings":
			if r.URL.Query().Get("inventory") != "7" {
				t.Errorf("asked about inventory %q", r.URL.Query().Get("inventory"))
			}
			asked++
			ready := asked > notReady
			_, _ = fmt.Fprintf(w, `{"inventory":{"id":7,"found":true,"ready":%t,"complete":true,"production":true},"findings":%s}`, ready, findings)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &asked
}

func scanWith(t *testing.T, srv *httptest.Server, args ...string) (int, string) {
	t.Helper()
	old := scanPoll
	scanPoll = 10 * time.Millisecond
	t.Cleanup(func() { scanPoll = old })
	dir := testutil.CopyDir(t, "../../testdata/fixtures/monorepo")
	var out strings.Builder
	code := Run(append(append([]string{"scan", "--server", srv.URL}, args...), dir), Env{Stdout: &out, Stderr: &out, Getenv: func(k string) string {
		if k == "WATCHDEP_TOKEN" {
			return "wdp_secret"
		}
		return ""
	}})
	return code, out.String()
}

// scan waits for the server's check and prints the part's open findings, most urgent first, with
// the version to move to.
func TestScanPrintsTheFindings(t *testing.T) {
	srv, asked := scanServer(t, 2, `[
		{"id":2,"primary_id":"Ruby 3.4","summary":"Ruby 3.4.7 is behind 3.4.12, the latest 3.4 release","level":"low","kind":"outdated","places":[{"name":"ruby","version":"3.4.7","fix":"3.4.12"}]},
		{"id":1,"primary_id":"CVE-2024-1","summary":"Shell escape in Rack","level":"high","kind":"vulnerability","places":[{"name":"rack","version":"2.2.3","fix":"2.2.8"}]},
		{"id":3,"primary_id":"GHSA-x","summary":"No fix yet","level":"medium","kind":"vulnerability","places":[{"name":"left-pad","version":"1.3.0","fix":""}]}]`)
	code, out := scanWith(t, srv)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if *asked != 3 {
		t.Fatalf("asked %d times, want 3 (two not ready, then ready)", *asked)
	}
	for _, want := range []string{"Checked: 3 open findings, 1 high, 1 medium, 1 low.", "rack 2.2.3 → 2.2.8", "ruby 3.4.7 → 3.4.12", "left-pad 1.3.0 no fixed version published", "http://x/inventories/7"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if !(strings.Index(out, "CVE-2024-1") < strings.Index(out, "GHSA-x") && strings.Index(out, "GHSA-x") < strings.Index(out, "Ruby 3.4")) {
		t.Fatalf("not most urgent first:\n%s", out)
	}
}

func TestScanSaysWhenClean(t *testing.T) {
	srv, _ := scanServer(t, 0, `[]`)
	if _, out := scanWith(t, srv); !strings.Contains(out, "Checked: no open findings.") {
		t.Fatalf("%s", out)
	}
}

// --wait 0 only sends; a check slower than --wait, or a server that does not say, prints the page.
func TestScanWaitLimits(t *testing.T) {
	srv, asked := scanServer(t, 0, `[]`)
	if _, out := scanWith(t, srv, "--wait", "0"); *asked != 0 || strings.Contains(out, "Checked") {
		t.Fatalf("--wait 0 asked %d times: %s", *asked, out)
	}
	ci, ciAsked := scanServer(t, 0, `[]`)
	old := scanPoll
	scanPoll = 10 * time.Millisecond
	defer func() { scanPoll = old }()
	var ciOut strings.Builder
	Run([]string{"scan", "--server", ci.URL, testutil.CopyDir(t, "../../testdata/fixtures/monorepo")}, Env{Stdout: &ciOut, Stderr: &ciOut,
		Getenv: func(k string) string { return map[string]string{"WATCHDEP_TOKEN": "wdp_secret", "CI": "true"}[k] }})
	if *ciAsked != 0 {
		t.Fatalf("in CI, scan only sends unless --wait is given: asked %d times\n%s", *ciAsked, ciOut.String())
	}
	slow, _ := scanServer(t, 1000, `[]`)
	code, out := scanWith(t, slow, "--wait", "50ms")
	if code != 0 || !strings.Contains(out, "still checking it") || !strings.Contains(out, "http://x/inventories/7") {
		t.Fatalf("exit %d: %s", code, out)
	}
}
