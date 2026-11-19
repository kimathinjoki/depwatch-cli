package cli

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kimathinjoki/watchdep-cli/internal/keys"
)

// The menus, driven as plain numbered prompts (the accessible mode a screen reader uses).
func runMenuWith(t *testing.T, store keys.Store, assistURL, answers string, args ...string) (int, string) {
	t.Helper()
	t.Setenv("WATCHDEP_CREDENTIALS", filepath.Join(t.TempDir(), "credentials.json"))
	var out strings.Builder
	code := Run(args, Env{Stdout: &out, Stderr: &out, Stdin: strings.NewReader(answers), Keys: store,
		Interactive: true, Accessible: true, AssistURL: assistURL, Getenv: func(string) string { return "" }})
	return code, out.String()
}

func fakeOpenAI(t *testing.T, status int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if status == 200 {
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-6.1-sol","object":"model","created":1,"owned_by":"openai"},{"id":"gpt-6.1-mini","object":"model","created":1,"owned_by":"openai"}]}`))
		} else {
			_, _ = w.Write([]byte(`{"error":{"message":"Incorrect API key provided","type":"invalid_request_error"}}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// watchdep keys walks through a provider: its key, checked with the provider before it is saved, a
// model from the provider's own list, and whether check --assist uses them by default.
func TestKeysMenuSetsUpAProvider(t *testing.T) {
	store := keys.Memory{}
	// Set up a provider (1), OpenAI (3), the key, the second model (2), use it by default (y), back (4).
	code, out := runMenuWith(t, store, fakeOpenAI(t, 200).URL, "1\n3\nsk-test\n2\ny\n4\n", "keys")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	for _, want := range []string{"Which provider?", "The key works: 2 models available.", "Saved in", "Which model?", "now uses OpenAI, gpt-6.1-sol"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q:\n%s", want, out)
		}
	}
	if store["openai"] != "sk-test" {
		t.Fatalf("saved %q", store["openai"])
	}
	prefs, _ := keys.LoadPrefs(prefsDir())
	if prefs != (keys.Prefs{Provider: "openai", Model: "gpt-6.1-sol"}) {
		t.Fatalf("%+v", prefs)
	}
	env := &Env{Keys: store, Getenv: func(string) string { return "" }}
	if p, m := assistDefaults(env, "", ""); p != "openai" || m != "gpt-6.1-sol" {
		t.Fatalf("check --assist would use %s %s", p, m)
	}
	if p, m := assistDefaults(env, "google", ""); p != "google" || m != "" {
		t.Fatalf("a named provider wins: %s %s", p, m)
	}
}

// A key the provider refuses is never saved.
func TestKeysMenuRefusedKeyIsNotSaved(t *testing.T) {
	store := keys.Memory{}
	code, out := runMenuWith(t, store, fakeOpenAI(t, 401).URL, "1\n3\nsk-wrong\n4\n", "keys")
	if code != 0 || !strings.Contains(out, "did not accept the key") || !strings.Contains(out, "Nothing was saved.") {
		t.Fatalf("exit %d: %s", code, out)
	}
	if len(store) != 0 {
		t.Fatalf("saved %v", store)
	}
}

// watchdep on its own opens the menu; each choice runs the command as typed, and Quit leaves.
func TestMainMenuRunsTheChosenCommand(t *testing.T) {
	code, out := runMenuWith(t, keys.Memory{}, "", "6\n7\n")
	if code != 0 || !strings.Contains(out, "What do you want to do?") || !strings.Contains(out, "$ watchdep inventory") {
		t.Fatalf("exit %d: %s", code, out)
	}
}

// Not in a terminal, watchdep and watchdep keys print their help, as before.
func TestNoMenuOutsideATerminal(t *testing.T) {
	for _, args := range [][]string{nil, {"keys"}} {
		var out strings.Builder
		code := Run(args, Env{Stdout: &out, Stderr: &out})
		if code != 0 || !strings.Contains(out.String(), "Usage:") || strings.Contains(out.String(), "What do you want to do?") {
			t.Fatalf("%v: exit %d: %s", args, code, out.String())
		}
	}
}
