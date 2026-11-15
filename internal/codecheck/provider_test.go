package codecheck

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeServer(t *testing.T, status int, body string, seen *map[string]any, path *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		if seen != nil {
			_ = json.Unmarshal(raw, seen)
		}
		if path != nil {
			*path = r.URL.Path
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// The provider comes from the flag, else the first key set; the model from the flag, else the default.
func TestChooseProviderAndModel(t *testing.T) {
	env := func(set map[string]string) func(string) string { return func(k string) string { return set[k] } }
	for _, tc := range []struct {
		flag string
		keys map[string]string
		want string
	}{
		{"", map[string]string{}, "anthropic"},
		{"", map[string]string{"GEMINI_API_KEY": "g"}, "google"},
		{"", map[string]string{"OPENAI_API_KEY": "o", "GEMINI_API_KEY": "g"}, "google"},
		{"openai", map[string]string{"ANTHROPIC_API_KEY": "a"}, "openai"},
	} {
		if got, err := ChooseProvider(tc.flag, env(tc.keys)); err != nil || got != tc.want {
			t.Fatalf("%q %v: %q %v", tc.flag, tc.keys, got, err)
		}
	}
	if _, err := ChooseProvider("mistral", env(nil)); err == nil {
		t.Fatal("an unknown provider is refused")
	}
	if m, _ := ChooseModel("google", ""); m != "gemini-4-carbon" {
		t.Fatal(m)
	}
	if _, err := ChooseModel("openai", ""); err == nil || !strings.Contains(err.Error(), "watchdep models --provider openai") {
		t.Fatalf("OpenAI has no default model: %v", err)
	}
}

func geminiBody(status, text string) string {
	b, _ := json.Marshal(map[string]any{"id": "i1", "model": "gemini-4-carbon", "status": status, "created": "2026-11-15T00:00:00Z",
		"updated": "2026-11-15T00:00:00Z", "output_text": text,
		"steps": []any{map[string]any{"type": "model_output", "content": []any{map[string]any{"type": "text", "text": text}}}}})
	return string(b)
}

// Gemini: the request asks for the schema at low thinking and for Google to keep nothing.
func TestGeminiProvider(t *testing.T) {
	var seen map[string]any
	var path string
	srv := fakeServer(t, 200, geminiBody("completed", `{"verdict":"used","reason":"src/a.js:2 calls it."}`), &seen, &path)
	p, err := newGemini(context.Background(), "gm-test", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := load(t, map[string]string{"src/a.js": "x\nconst axios = require('axios')\n"})
	f := npm("axios", "direct")
	r, err := NewAssistant(p, "gemini-4-carbon").Refine(context.Background(), f, c.Check(f), c)
	if err != nil || r.Verdict != Used || !r.Assisted || r.Model != "gemini-4-carbon" {
		t.Fatalf("%+v %v", r, err)
	}
	if path != "/v1beta/interactions" || seen["store"] != false || seen["model"] != "gemini-4-carbon" {
		t.Fatalf("%s %v", path, seen)
	}
	gc, _ := seen["generation_config"].(map[string]any)
	rf, _ := seen["response_format"].(map[string]any)
	if gc["thinking_level"] != "low" || rf["mime_type"] != "application/json" || rf["schema"] == nil {
		t.Fatalf("%v %v", gc, rf)
	}
}

// Gemini: a safety block and a cut-short answer keep the search's verdict.
func TestGeminiFailuresKeepTheSearch(t *testing.T) {
	c := load(t, map[string]string{"src/a.js": "const axios = require('axios')\n"})
	f := npm("axios", "direct")
	draft := c.Check(f)
	for _, srv := range []*httptest.Server{
		fakeServer(t, 400, `{"error":{"code":"safety","message":"blocked"}}`, nil, nil),
		fakeServer(t, 200, geminiBody("incomplete", `{"verdict":`), nil, nil),
		fakeServer(t, 503, `{"error":{"code":"unavailable"}}`, nil, nil),
	} {
		p, _ := newGemini(context.Background(), "k", srv.URL)
		r, err := NewAssistant(p, "gemini-4-carbon").Refine(context.Background(), f, draft, c)
		if err == nil || r.Verdict != draft.Verdict || r.Assisted || !strings.Contains(r.Reason, "The assistant was not used") {
			t.Fatalf("%+v %v", r, err)
		}
	}
}

func openaiBody(content []any, status string) string {
	b, _ := json.Marshal(map[string]any{"id": "r1", "object": "response", "created_at": 1, "model": "gpt-6.1-sol", "status": status,
		"output":              []any{map[string]any{"type": "message", "id": "m1", "role": "assistant", "status": "completed", "content": content}},
		"parallel_tool_calls": false, "tool_choice": "auto", "tools": []any{},
		"usage": map[string]any{"input_tokens": 10, "output_tokens": 5, "total_tokens": 15, "input_tokens_details": map[string]any{"cached_tokens": 0}, "output_tokens_details": map[string]any{"reasoning_tokens": 0}}})
	return string(b)
}

// OpenAI: a strict schema, low reasoning, nothing stored; a refusal keeps the search's verdict.
func TestOpenAIProvider(t *testing.T) {
	var seen map[string]any
	srv := fakeServer(t, 200, openaiBody([]any{map[string]any{"type": "output_text", "text": `{"verdict":"unclear","reason":"only a transitive path."}`, "annotations": []any{}}}, "completed"), &seen, nil)
	c := load(t, map[string]string{"src/a.js": "const axios = require('axios')\n"})
	f := npm("axios", "direct")
	r, err := NewAssistant(newOpenAI("sk-o", srv.URL), "gpt-6.1-sol").Refine(context.Background(), f, c.Check(f), c)
	if err != nil || r.Verdict != Unclear || r.Model != "gpt-6.1-sol" {
		t.Fatalf("%+v %v", r, err)
	}
	text, _ := seen["text"].(map[string]any)
	format, _ := text["format"].(map[string]any)
	reasoning, _ := seen["reasoning"].(map[string]any)
	if seen["store"] != false || format["strict"] != true || format["type"] != "json_schema" || reasoning["effort"] != "low" {
		t.Fatalf("%v", seen)
	}

	refused := fakeServer(t, 200, openaiBody([]any{map[string]any{"type": "refusal", "refusal": "no"}}, "completed"), nil, nil)
	draft := c.Check(f)
	r, err = NewAssistant(newOpenAI("sk-o", refused.URL), "gpt-6.1-sol").Refine(context.Background(), f, draft, c)
	if err == nil || r.Verdict != draft.Verdict || r.Assisted {
		t.Fatalf("%+v %v", r, err)
	}
}

// Model lists: Gemini models that think; OpenAI's gpt models.
func TestModelLists(t *testing.T) {
	g := fakeServer(t, 200, `{"models":[{"name":"models/gemini-4-carbon","thinking":true},{"name":"models/text-embedding-9","thinking":false}]}`, nil, nil)
	gp, _ := newGemini(context.Background(), "k", g.URL)
	ids, err := gp.Models(context.Background())
	if err != nil || len(ids) != 1 || ids[0] != "gemini-4-carbon" {
		t.Fatalf("%v %v", ids, err)
	}
	o := fakeServer(t, 200, `{"object":"list","data":[{"id":"gpt-6.1-sol","object":"model","created":1,"owned_by":"openai"},{"id":"whisper-9","object":"model","created":1,"owned_by":"openai"}]}`, nil, nil)
	ids, err = newOpenAI("k", o.URL).Models(context.Background())
	if err != nil || len(ids) != 1 || ids[0] != "gpt-6.1-sol" {
		t.Fatalf("%v %v", ids, err)
	}
}
