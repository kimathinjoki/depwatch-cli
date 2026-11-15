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

// check --assist takes the provider from the key set (or --provider), and OpenAI needs a model named.
func TestCheckAssistProviders(t *testing.T) {
	var sent map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	gemini := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"i","model":"gemini-4-carbon","status":"completed","created":"2026-11-15T00:00:00Z","updated":"2026-11-15T00:00:00Z",
		  "steps":[{"type":"model_output","content":[{"type":"text","text":"{\"verdict\":\"used\",\"reason\":\"src/api.js:1 imports it.\"}"}]}]}`))
	}))
	defer gemini.Close()
	dir := testutil.Tree(t, map[string]string{"src/api.js": "import axios from 'axios'\n"})
	keys := map[string]string{"DEPWATCH_SERVER": srv.URL, "DEPWATCH_TOKEN": "dwp_t", "GEMINI_API_KEY": "gm"}
	var out strings.Builder
	env := Env{Stdout: &out, Stderr: &out, Getenv: func(k string) string { return keys[k] }}
	if code := Run([]string{"check", dir, "--assist", "--assist-base-url", gemini.URL}, env); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	r := sent["results"].([]any)[0].(map[string]any)
	if r["assisted"] != true || r["model"] != "gemini-4-carbon" {
		t.Fatalf("the Gemini key chose Gemini: %v", r)
	}

	keys["OPENAI_API_KEY"] = "sk-o"
	out.Reset()
	if code := Run([]string{"check", dir, "--assist", "--provider", "openai"}, env); code != ExitUsage || !strings.Contains(out.String(), "depwatch models --provider openai") {
		t.Fatalf("OpenAI with no model: exit %d: %s", code, out.String())
	}
	out.Reset()
	if code := Run([]string{"check", dir, "--assist", "--provider", "mistral"}, env); code != ExitUsage {
		t.Fatalf("unknown provider: exit %d", code)
	}
}

// depwatch models lists a provider's models with the key from the environment.
func TestModels(t *testing.T) {
	gemini := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"models":[{"name":"models/gemini-4-argon","thinking":true},{"name":"models/gemini-4-carbon","thinking":true}]}`))
	}))
	defer gemini.Close()
	var out strings.Builder
	env := Env{Stdout: &out, Stderr: &out, Getenv: func(k string) string { return map[string]string{"GEMINI_API_KEY": "gm"}[k] }}
	if code := Run([]string{"models", "--provider", "google", "--base-url", gemini.URL}, env); code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	if !strings.Contains(out.String(), "gemini-4-argon\n") || !strings.Contains(out.String(), "gemini-4-carbon  (default)") {
		t.Fatalf("%q", out.String())
	}
	out.Reset()
	if code := Run([]string{"models"}, env); code != ExitUsage {
		t.Fatalf("no provider: exit %d", code)
	}
	out.Reset()
	if code := Run([]string{"models", "--provider", "openai"}, env); code != ExitUsage || !strings.Contains(out.String(), "OPENAI_API_KEY") {
		t.Fatalf("no key: exit %d %s", code, out.String())
	}
}
