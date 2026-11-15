package codecheck

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// A Provider answers a prompt in a JSON schema, from the person's machine with their own key. Anthropic,
// Google and OpenAI each implement it with their official Go SDK; none is reached in the tests.
type Provider interface {
	// Name is the provider's flag value: anthropic, google or openai.
	Name() string
	// Draft answers in the schema. Refused is set when the provider declined; the error is set when it
	// could not answer at all.
	Draft(ctx context.Context, model, system, user string, schema map[string]any) (Draft, error)
	// Models lists the provider's current models that can answer in a schema.
	Models(ctx context.Context) ([]string, error)
}

// Draft is a provider's answer.
type Draft struct {
	Text    string
	Model   string // the model that answered (a fallback model, when the provider used one)
	Refused bool
	Detail  string // why it was refused or cut short
}

// Providers, in the order a key in the environment chooses them when --provider is not given.
var Providers = []string{"anthropic", "google", "openai"}

// DefaultModels are the two defaults; OpenAI has none, so its model is always chosen.
var DefaultModels = map[string]string{"anthropic": "claude-opus-5-5", "google": "gemini-4-carbon"}

// KeyEnv names each provider's key variable. Anthropic also accepts an Anthropic login.
var KeyEnv = map[string]string{"anthropic": "ANTHROPIC_API_KEY", "google": "GEMINI_API_KEY", "openai": "OPENAI_API_KEY"}

// ChooseProvider picks the flag's provider, else the first with a key in the environment.
func ChooseProvider(flag string, getenv func(string) string) (string, error) {
	if flag != "" {
		for _, p := range Providers {
			if p == flag {
				return p, nil
			}
		}
		return "", fmt.Errorf("unknown provider %q: use anthropic, google or openai", flag)
	}
	for _, p := range Providers {
		if getenv(KeyEnv[p]) != "" {
			return p, nil
		}
	}
	// No key set: Anthropic, which can still use an Anthropic login.
	return "anthropic", nil
}

// ChooseModel is the flag's model, else the provider's default; OpenAI needs one named.
func ChooseModel(provider, flag string) (string, error) {
	if flag != "" {
		return flag, nil
	}
	if m, ok := DefaultModels[provider]; ok {
		return m, nil
	}
	return "", fmt.Errorf("%s has no default model: choose one with --model (watchdep models --provider %s lists them)", provider, provider)
}

// NewProvider builds the provider with its key from getenv. baseURL points it elsewhere (tests).
func NewProvider(ctx context.Context, name, baseURL string, getenv func(string) string) (Provider, error) {
	key := getenv(KeyEnv[name])
	switch name {
	case "anthropic":
		return newAnthropic(key, baseURL), nil
	case "google":
		if key == "" {
			return nil, errors.New("GEMINI_API_KEY is not set")
		}
		return newGemini(ctx, key, baseURL)
	case "openai":
		if key == "" {
			return nil, errors.New("OPENAI_API_KEY is not set")
		}
		return newOpenAI(key, baseURL), nil
	}
	return nil, fmt.Errorf("unknown provider %q", name)
}

func sorted(ids []string) []string {
	sort.Strings(ids)
	out := ids[:0]
	for i, id := range ids {
		if i == 0 || id != ids[i-1] {
			out = append(out, id)
		}
	}
	return out
}

func hasPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}
