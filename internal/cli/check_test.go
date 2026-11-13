package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kimathinjoki/depwatch-cli/internal/testutil"
)

func TestCheckFetchesSearchesAndSends(t *testing.T) {
	var sent map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer dwp_t" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/api/v1/findings":
			_, _ = w.Write([]byte(`{"part":"client","snippets_allowed":false,"findings":[{"id":7,"primary_id":"CVE-1","summary":"ssrf","symbols":[],
			  "places":[{"kind":"package","ecosystem":"npm","name":"axios","version":"1.7.4","relation":"direct","paths":[["axios"]]}]}]}`))
		case "/api/v1/code_checks":
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &sent)
			_, _ = w.Write([]byte(`{"stored":1}`))
		}
	}))
	defer srv.Close()
	dir := testutil.Tree(t, map[string]string{"src/api.js": "import axios from 'axios'\nexport const get = axios.get\n"})
	var out strings.Builder
	env := Env{Stdout: &out, Stderr: &out, Getenv: func(k string) string {
		return map[string]string{"DEPWATCH_SERVER": srv.URL, "DEPWATCH_TOKEN": "dwp_t"}[k]
	}}
	if code := Run([]string{"check", dir}, env); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	results := sent["results"].([]any)
	r := results[0].(map[string]any)
	if r["finding_id"] != float64(7) || r["verdict"] != "used" {
		t.Fatalf("%v", r)
	}
	ev := r["evidence"].([]any)[0].(map[string]any)
	if ev["path"] != "src/api.js" || ev["line"] != float64(1) || ev["snippet"] != nil {
		t.Fatalf("evidence %v: only path and line leave the machine without snippets", ev)
	}
	if !strings.Contains(out.String(), "a person decides") {
		t.Fatalf("%s", out.String())
	}
	bad := env
	bad.Getenv = func(k string) string {
		return map[string]string{"DEPWATCH_SERVER": srv.URL, "DEPWATCH_TOKEN": "dwp_x"}[k]
	}
	if code := Run([]string{"check", dir}, bad); code != ExitUsage {
		t.Fatalf("refused token: exit %d", code)
	}
}
