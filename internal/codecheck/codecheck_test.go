package codecheck

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go/v2/option"

	"github.com/kimathinjoki/depwatch-cli/internal/testutil"
)

func load(t *testing.T, files map[string]string) *Code {
	t.Helper()
	c, err := Load(testutil.Tree(t, files))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func npm(name, relation string, symbols ...string) Finding {
	return Finding{ID: 1, PrimaryID: "CVE-1", Summary: "flaw", Symbols: symbols,
		Places: []Place{{Kind: "package", Ecosystem: "npm", Name: name, Version: "1.0.0", Relation: relation, Paths: [][]string{{"express", name}}}}}
}

// An npm package imported with require and with import from is found with file and line.
func TestNpmImports(t *testing.T) {
	c := load(t, map[string]string{
		"src/a.js":                    "const x = 1\nconst axios = require('axios')\n",
		"src/b.ts":                    "import { get } from \"axios/lib/core\"\n",
		"node_modules/axios/index.js": "require('axios')",
		"dist/bundle.js":              "require('axios')",
		"src/unrelated.js":            "import 'axios-retry'\n",
	})
	r := c.Check(npm("axios", "direct"))
	if r.Verdict != Used || len(r.Evidence) != 2 {
		t.Fatalf("%+v", r)
	}
	if r.Evidence[0].Path != "src/a.js" || r.Evidence[0].Line != 2 || r.Evidence[1].Path != "src/b.ts" {
		t.Fatalf("%+v", r.Evidence)
	}
}

// A Python distribution name maps to its module.
func TestPythonModules(t *testing.T) {
	c := load(t, map[string]string{"app/upload.py": "from multipart import parse_form\nimport yaml\n"})
	f := Finding{ID: 2, Places: []Place{{Kind: "package", Ecosystem: "PyPI", Name: "python-multipart", Relation: "direct"}}}
	if r := c.Check(f); r.Verdict != Used || r.Evidence[0].Line != 1 {
		t.Fatalf("%+v", r)
	}
	f.Places[0].Name = "PyYAML"
	if r := c.Check(f); r.Verdict != Used || r.Evidence[0].Line != 2 {
		t.Fatalf("%+v", r)
	}
}

// A named affected function called in an importing file makes the verdict used; imported with functions
// named but none called is unclear.
func TestAffectedFunctions(t *testing.T) {
	c := load(t, map[string]string{"main.go": "package main\n\nimport \"golang.org/x/net/html\"\n\nfunc f() { html.Parse(nil) }\n"})
	f := Finding{ID: 3, Symbols: []string{"html.Parse"}, Places: []Place{{Kind: "package", Ecosystem: "Go", Name: "golang.org/x/net", Relation: "direct"}}}
	r := c.Check(f)
	if r.Verdict != Used || r.Evidence[1].Line != 5 || !strings.Contains(r.Evidence[1].Note, "calls Parse") {
		t.Fatalf("%+v", r)
	}
	f.Symbols = []string{"html.Tokenize"}
	if r := c.Check(f); r.Verdict != Unclear {
		t.Fatalf("%+v", r)
	}
}

// A direct dependency imported nowhere is not used; a transitive one is unclear, naming what brings it in.
func TestNotImported(t *testing.T) {
	c := load(t, map[string]string{"src/a.js": "console.log(1)\n"})
	if r := c.Check(npm("lodash", "direct")); r.Verdict != NotUsed {
		t.Fatalf("%+v", r)
	}
	r := c.Check(npm("qs", "transitive"))
	if r.Verdict != Unclear || !strings.Contains(r.Reason, "through express") {
		t.Fatalf("%+v", r)
	}
}

// No source files of the package's language: unclear, never not used.
func TestNoSources(t *testing.T) {
	c := load(t, map[string]string{"README.md": "hi"})
	if r := c.Check(npm("lodash", "direct")); r.Verdict != Unclear {
		t.Fatalf("%+v", r)
	}
}

func TestRubyRequires(t *testing.T) {
	c := load(t, map[string]string{"config.ru": "require \"rack\"\nrun App\n", "app/x.rb": "require 'action_dispatch'\n"})
	f := Finding{ID: 4, Places: []Place{{Kind: "package", Ecosystem: "RubyGems", Name: "actionpack", Relation: "transitive"}}}
	if r := c.Check(f); r.Verdict != Used || r.Evidence[0].Path != "app/x.rb" {
		t.Fatalf("%+v", r)
	}
}

func fakeClaude(t *testing.T, status int, body string, seen *map[string]any) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if seen != nil {
			_ = json.Unmarshal(raw, seen)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func message(text, stop string) string {
	b, _ := json.Marshal(map[string]any{"id": "msg_1", "type": "message", "role": "assistant", "model": "claude-opus-5-5",
		"content": []map[string]any{{"type": "text", "text": text}}, "stop_reason": stop,
		"usage": map[string]any{"input_tokens": 10, "output_tokens": 10}})
	return string(b)
}

// The request carries the evidence and asks for structured output; the verdict and reason come back.
func TestAssistant(t *testing.T) {
	var seen map[string]any
	srv := fakeClaude(t, 200, message(`{"verdict":"used","reason":"src/a.js:2 calls it on every request."}`, "end_turn"), &seen)
	defer srv.Close()
	c := load(t, map[string]string{"src/a.js": "x\nconst axios = require('axios')\n"})
	f := npm("axios", "direct")
	a := NewAssistant("", option.WithBaseURL(srv.URL), option.WithAPIKey("test"), option.WithMaxRetries(0))
	r, err := a.Refine(context.Background(), f, c.Check(f), c)
	if err != nil || r.Verdict != Used || !r.Assisted || r.Model != "claude-opus-5-5" || !strings.Contains(r.Reason, "every request") {
		t.Fatalf("%+v %v", r, err)
	}
	oc := seen["output_config"].(map[string]any)
	if oc["format"].(map[string]any)["type"] != "json_schema" || seen["model"] != DefaultModel || seen["fallbacks"] != "default" {
		t.Fatalf("request: %v", seen)
	}
	msgs, _ := json.Marshal(seen["messages"])
	if !strings.Contains(string(msgs), "src/a.js:2") {
		t.Fatalf("the evidence was not sent: %s", msgs)
	}
}

// An API error, a refusal or an unreadable answer keeps the search's verdict and says so.
func TestAssistantFailuresKeepTheSearch(t *testing.T) {
	c := load(t, map[string]string{"src/a.js": "const axios = require('axios')\n"})
	f := npm("axios", "direct")
	draft := c.Check(f)
	for _, srv := range []*httptest.Server{
		fakeClaude(t, 400, `{"type":"error","error":{"type":"invalid_request_error","message":"bad"}}`, nil),
		fakeClaude(t, 200, message("", "refusal"), nil),
		fakeClaude(t, 200, message("not json", "end_turn"), nil),
		fakeClaude(t, 200, message(`{"verdict":"not_used","reason":"x"}`, "end_turn"), nil),
	} {
		a := NewAssistant("", option.WithBaseURL(srv.URL), option.WithAPIKey("test"), option.WithMaxRetries(0))
		r, _ := a.Refine(context.Background(), f, draft, c)
		srv.Close()
		if r.Verdict == NotUsed {
			t.Fatalf("a found use became not used: %+v", r)
		}
	}
}
