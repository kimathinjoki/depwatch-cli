package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kimathinjoki/depwatch-cli/internal/testutil"
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
		gotAuth = r.Header.Get("Authorization")
		gotBody, _ = io.ReadAll(r.Body)
		if r.URL.Path != "/api/v1/inventories" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"part":"api","application":"Prospec360","inventory_id":7,"production":true,"url":"http://x/inventories/7"}`))
	}))
	defer srv.Close()
	dir := testutil.CopyDir(t, "../../testdata/fixtures/monorepo")
	var out strings.Builder
	code := Run([]string{"scan", "--server", srv.URL, dir}, Env{Stdout: &out, Stderr: &out, Getenv: func(k string) string {
		if k == "DEPWATCH_TOKEN" {
			return "dwp_secret"
		}
		return ""
	}})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if gotAuth != "Bearer dwp_secret" {
		t.Fatalf("auth %q", gotAuth)
	}
	_, inv, _ := run(t, nil, "inventory", "--json", dir)
	a, b := dropTakenAt(t, gotBody), dropTakenAt(t, []byte(inv))
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Fatalf("scan sent a different inventory:\n%s\n%s", ja, jb)
	}
	if !strings.Contains(out.String(), "production") || !strings.Contains(out.String(), "Prospec360") {
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
			if k == "DEPWATCH_TOKEN" {
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
	t.Setenv("DEPWATCH_CREDENTIALS", filepath.Join(t.TempDir(), "none.json"))
	noTok := Env{Stdout: io.Discard, Stderr: io.Discard}
	if code := Run([]string{"scan", dir}, noTok); code != ExitUsage {
		t.Fatalf("no token: exit %d", code)
	}
}

// A server that will not look now (429, the plan's scans for today are used) is not a clean result:
// scan prints the server's reason and exits 2. depwatch-server's InventoriesController answers this.
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
		if k == "DEPWATCH_TOKEN" {
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

// The stored credentials file is created with owner-only permissions, and scan uses it.
func TestLoginStoresPrivately(t *testing.T) {
	p := filepath.Join(t.TempDir(), "depwatch", "credentials.json")
	t.Setenv("DEPWATCH_CREDENTIALS", p)
	if code, out, _ := run(t, nil, "login", "--server", "https://dw.example.test/", "--token", "dwp_abc"); code != 0 {
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
	if !strings.Contains(string(raw), `"https://dw.example.test": "dwp_abc"`) {
		t.Fatalf("%s", raw)
	}
	srv, tok, err := resolveServer(&Env{Getenv: func(string) string { return "" }}, "", "")
	if err != nil || srv != "https://dw.example.test" || tok != "dwp_abc" {
		t.Fatalf("%s %s %v", srv, tok, err)
	}
	if code, _, _ := run(t, nil, "login", "--server", "not a url", "--token", "x"); code != ExitUsage {
		t.Fatalf("bad server: exit %d", code)
	}
}
