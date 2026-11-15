package codecheck

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
	a := NewAssistant(newAnthropic("test", srv.URL), DefaultModel)
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
		a := NewAssistant(newAnthropic("test", srv.URL), DefaultModel)
		r, _ := a.Refine(context.Background(), f, draft, c)
		srv.Close()
		if r.Verdict == NotUsed {
			t.Fatalf("a found use became not used: %+v", r)
		}
	}
}

func gem(name string) Finding {
	return Finding{ID: 5, Places: []Place{{Kind: "package", Ecosystem: "RubyGems", Name: name, Relation: "direct"}}}
}

func pypi(name string) Finding {
	return Finding{ID: 6, Places: []Place{{Kind: "package", Ecosystem: "PyPI", Name: name, Relation: "direct"}}}
}

// A gem Bundler.require loads at boot may be used with no require line: the verdict is unclear, never
// not used. A gem declared with require: false is not loaded that way, and its require name is known.
func TestRubyBundlerRequireIsUnclear(t *testing.T) {
	c := load(t, map[string]string{
		"Gemfile":               "source 'https://rubygems.org'\ngem \"devise\"\ngem 'nokogiri', require: false\n",
		"config/application.rb": "require_relative \"boot\"\nrequire \"rails/all\"\nBundler.require(*Rails.groups)\n",
		"app/models/user.rb":    "class User < ApplicationRecord\n  devise :database_authenticatable\nend\n",
	})
	r := c.Check(gem("devise"))
	if r.Verdict != Unclear || !strings.Contains(r.Reason, "Bundler.require") {
		t.Fatalf("%+v", r)
	}
	if r := c.Check(gem("nokogiri")); r.Verdict != NotUsed {
		t.Fatalf("a gem with require: false and a known require name, required nowhere: %+v", r)
	}
	// A gem whose require name is not known is unclear even without Bundler.require.
	if r := c.Check(gem("ruby-saml")); r.Verdict != Unclear {
		t.Fatalf("%+v", r)
	}
}

// A gem's require name is read from the gems installed in vendor/bundle when it is not a known one.
func TestRubyInstalledGemNames(t *testing.T) {
	c := load(t, map[string]string{
		"vendor/bundle/ruby/3.3.0/gems/ruby-saml-1.16.0/lib/onelogin/ruby-saml.rb": "",
		"vendor/bundle/ruby/3.3.0/gems/ruby-saml-1.16.0/lib/ruby-saml.rb":          "",
		"app/sso.rb":   "require 'onelogin/ruby-saml'\n",
		"app/other.rb": "puts 1\n",
	})
	if r := c.Check(gem("ruby-saml")); r.Verdict != Used {
		t.Fatalf("%+v", r)
	}
	c = load(t, map[string]string{
		"vendor/bundle/ruby/3.3.0/gems/ruby-saml-1.16.0/lib/ruby-saml.rb": "",
		"app/other.rb": "puts 1\n",
	})
	if r := c.Check(gem("ruby-saml")); r.Verdict != NotUsed {
		t.Fatalf("%+v", r)
	}
}

// A Python package whose import name is not known (pycryptodome is imported as Crypto) is never
// called not used on a guess.
func TestPythonUnknownModuleIsUnclear(t *testing.T) {
	c := load(t, map[string]string{"app/sign.py": "from Crypto.Cipher import AES\n"})
	if r := c.Check(pypi("pycryptodome")); r.Verdict != Used {
		t.Fatalf("pycryptodome is imported as Crypto: %+v", r)
	}
	r := c.Check(pypi("some-obscure-dist"))
	if r.Verdict != Unclear || !strings.Contains(r.Reason, "not known") {
		t.Fatalf("%+v", r)
	}
	if r := c.Check(pypi("requests")); r.Verdict != NotUsed {
		t.Fatalf("requests is imported as requests: %+v", r)
	}
}

// The import name of a Python package installed in the part's virtual environment comes from its
// metadata.
func TestPythonInstalledModuleNames(t *testing.T) {
	c := load(t, map[string]string{
		".venv/lib/python3.12/site-packages/some_obscure_dist-2.0.dist-info/top_level.txt": "obscure\n",
		"app/main.py": "import obscure.thing\n",
	})
	if r := c.Check(pypi("some-obscure-dist")); r.Verdict != Used {
		t.Fatalf("%+v", r)
	}
	c = load(t, map[string]string{
		".venv/lib/python3.12/site-packages/some_obscure_dist-2.0.dist-info/top_level.txt": "obscure\n",
		"app/main.py": "import os\n",
	})
	if r := c.Check(pypi("some-obscure-dist")); r.Verdict != NotUsed {
		t.Fatalf("%+v", r)
	}
}

// Ecosystems whose import names cannot be told from the package name (Maven group ids, Composer
// vendors, NuGet ids, Hex packages) are unclear when no import is found.
func TestUnknownMappingIsUnclear(t *testing.T) {
	c := load(t, map[string]string{"src/App.java": "import java.util.List;\n", "src/a.php": "<?php\n", "lib/a.ex": "defmodule A do\nend\n"})
	for _, p := range []Place{
		{Kind: "package", Ecosystem: "Maven", Name: "commons-collections:commons-collections", Relation: "direct"},
		{Kind: "package", Ecosystem: "Packagist", Name: "swiftmailer/swiftmailer", Relation: "direct"},
		{Kind: "package", Ecosystem: "Hex", Name: "plug_cowboy", Relation: "direct"},
	} {
		if r := c.Check(Finding{ID: 7, Places: []Place{p}}); r.Verdict != Unclear {
			t.Fatalf("%s: %+v", p.Name, r)
		}
	}
}

// A source file that could not be searched (over 1 MB) means the search did not cover the code: no
// not used.
func TestUnsearchedFileIsUnclear(t *testing.T) {
	c := load(t, map[string]string{"src/a.js": "console.log(1)\n", "src/big.js": strings.Repeat("x", 1<<20+1)})
	if r := c.Check(npm("lodash", "direct")); r.Verdict != Unclear || !strings.Contains(r.Reason, "could not be searched") {
		t.Fatalf("%+v", r)
	}
}

// A Rust crate used by its path with no use line is found.
func TestRustPathUse(t *testing.T) {
	c := load(t, map[string]string{"src/main.rs": "fn main() {\n    let v = serde_json::from_str::<u8>(\"1\");\n}\n"})
	f := Finding{ID: 8, Places: []Place{{Kind: "package", Ecosystem: "crates.io", Name: "serde-json", Relation: "direct"}}}
	if r := c.Check(f); r.Verdict != Used {
		t.Fatalf("%+v", r)
	}
}
