package cli

import (
	"strings"
	"testing"

	"github.com/kimathinjoki/watchdep-cli/internal/keys"
)

func runKeys(t *testing.T, store keys.Store, getenv func(string) string, stdin string, args ...string) (int, string) {
	t.Helper()
	var out strings.Builder
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	code := Run(args, Env{Stdout: &out, Stderr: &out, Getenv: getenv, Stdin: strings.NewReader(stdin), Keys: store})
	return code, out.String()
}

// A key piped in is saved under its provider, listed by where it comes from (never shown), and
// removed; a key in the environment wins over a saved one.
func TestKeysSetListRemove(t *testing.T) {
	store := keys.Memory{}
	if code, out := runKeys(t, store, nil, "  sk-ant-secret\n", "keys", "set", "anthropic"); code != 0 || !strings.Contains(out, "Saved the Anthropic key") {
		t.Fatalf("exit %d: %s", code, out)
	}
	if store["anthropic"] != "sk-ant-secret" {
		t.Fatalf("saved %q", store["anthropic"])
	}
	env := func(k string) string { return map[string]string{"GEMINI_API_KEY": "g"}[k] }
	_, out := runKeys(t, store, env, "", "keys", "list")
	if !strings.Contains(out, "anthropic  saved in") || !strings.Contains(out, "google     the environment (GEMINI_API_KEY)") || !strings.Contains(out, "openai     none") {
		t.Fatalf("%s", out)
	}
	if strings.Contains(out, "sk-ant-secret") {
		t.Fatal("list never shows a key")
	}
	if code, out := runKeys(t, store, nil, "", "keys", "remove", "anthropic"); code != 0 || !strings.Contains(out, "Deleted the saved Anthropic key") || len(store) != 0 {
		t.Fatalf("exit %d: %s %v", code, out, store)
	}
	if _, out := runKeys(t, store, nil, "", "keys", "remove", "anthropic"); !strings.Contains(out, "No Anthropic key was saved") {
		t.Fatalf("%s", out)
	}
}

func TestKeysRefusesNoKeyOrUnknownProvider(t *testing.T) {
	if code, _ := runKeys(t, keys.Memory{}, nil, "\n", "keys", "set", "anthropic"); code != ExitUsage {
		t.Fatalf("an empty key: exit %d", code)
	}
	if code, _ := runKeys(t, keys.Memory{}, nil, "k\n", "keys", "set", "mistral"); code != ExitUsage {
		t.Fatalf("an unknown provider: exit %d", code)
	}
}

// check --assist and models take the environment's key first, then the saved one.
func TestProviderEnvPrefersTheEnvironment(t *testing.T) {
	store := keys.Memory{"anthropic": "saved-a", "openai": "saved-o"}
	env := &Env{Keys: store, Getenv: func(k string) string { return map[string]string{"ANTHROPIC_API_KEY": "env-a"}[k] }}
	get := providerEnv(env)
	if get("ANTHROPIC_API_KEY") != "env-a" || get("OPENAI_API_KEY") != "saved-o" || get("GEMINI_API_KEY") != "" || get("PATH") != "" {
		t.Fatalf("%q %q %q", get("ANTHROPIC_API_KEY"), get("OPENAI_API_KEY"), get("GEMINI_API_KEY"))
	}
}
