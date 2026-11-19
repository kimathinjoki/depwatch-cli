package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/kimathinjoki/watchdep-cli/internal/client"
	"github.com/kimathinjoki/watchdep-cli/internal/codecheck"
	"github.com/kimathinjoki/watchdep-cli/internal/keys"
)

var providerNames = map[string]string{"anthropic": "Anthropic", "google": "Google (Gemini)", "openai": "OpenAI"}

func newKeys(env *Env) *cobra.Command {
	c := &cobra.Command{
		Use:   "keys",
		Short: "Save the AI keys check --assist uses, in your system's keychain",
		Long: `Save an AI provider's key once, in your system's own store (the macOS Keychain, Windows Credential
Manager, or your keyring on Linux), so check --assist and models find it in every terminal without an
environment variable. The key never goes to the watchdep server, and watchdep never writes it to a file
of its own. A key in the environment (ANTHROPIC_API_KEY, GEMINI_API_KEY, OPENAI_API_KEY) wins over a
saved one, so CI is unchanged.

On its own in a terminal, watchdep keys walks through it: choose a provider, paste its key, see it
checked with the provider, choose a model, and whether check --assist uses them by default.`,
		Args: cobra.NoArgs,
		// On its own in a terminal, a menu: set up a provider, remove a key, see what is set up.
		RunE: func(c *cobra.Command, _ []string) error {
			if env.Interactive {
				err := keysMenu(env)
				if errors.Is(err, errQuit) {
					return nil
				}
				return err
			}
			return c.Help()
		},
	}
	c.AddCommand(newKeysSet(env), newKeysList(env), newKeysRemove(env))
	return c
}

func providerArg(args []string) (string, error) {
	if len(args) != 1 || providerNames[args[0]] == "" {
		return "", &usageError{msg: "name a provider: anthropic, google or openai"}
	}
	return args[0], nil
}

func newKeysSet(env *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "set anthropic|google|openai",
		Short: "Save a provider's key (asked for without showing it, or read from standard input)",
		Args:  cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error {
			p, err := providerArg(args)
			if err != nil {
				return err
			}
			var key string
			if f, ok := env.Stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
				fmt.Fprintf(env.Stderr, "Paste your %s API key (it is not shown): ", providerNames[p])
				raw, err := term.ReadPassword(int(f.Fd()))
				fmt.Fprintln(env.Stderr)
				if err != nil {
					return err
				}
				key = string(raw)
			} else {
				line, err := bufio.NewReader(c.InOrStdin()).ReadString('\n')
				if err != nil && line == "" {
					return &usageError{msg: "no key given: run it in a terminal to be asked, or pipe the key in"}
				}
				key = line
			}
			key = strings.TrimSpace(key)
			if key == "" {
				return &usageError{msg: "no key given"}
			}
			if err := env.Keys.Set(p, key); err != nil {
				return fmt.Errorf("could not save the key in %s (%v): set %s in the environment instead", keys.Name(), err, codecheck.KeyEnv[p])
			}
			fmt.Fprintf(env.Stdout, "Saved the %s key in %s. check --assist and models use it from now on.\n", providerNames[p], keys.Name())
			if env.Getenv(codecheck.KeyEnv[p]) != "" {
				fmt.Fprintf(env.Stdout, "%s is set in this environment, and wins over the saved key while it is.\n", codecheck.KeyEnv[p])
			}
			return nil
		},
	}
}

func newKeysList(env *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "Say which providers have a key, and where it comes from (never the key)",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			rows := map[string]string{}
			for _, p := range codecheck.Providers {
				where := "none"
				if env.Getenv(codecheck.KeyEnv[p]) != "" {
					where = "the environment (" + codecheck.KeyEnv[p] + ")"
				} else if _, err := env.Keys.Get(p); err == nil {
					where = "saved in " + keys.Name()
				} else if !errors.Is(err, keys.ErrNotFound) {
					where = "could not read " + keys.Name() + ": " + err.Error()
				}
				rows[p] = where
			}
			if jsonFlag(c) {
				return writeJSON(env.Stdout, rows)
			}
			for _, p := range codecheck.Providers {
				fmt.Fprintf(env.Stdout, "%-10s %s\n", p, rows[p])
			}
			return nil
		},
	}
}

func newKeysRemove(env *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "remove anthropic|google|openai",
		Short: "Delete a provider's saved key",
		Args:  cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error {
			p, err := providerArg(args)
			if err != nil {
				return err
			}
			switch err := env.Keys.Delete(p); {
			case errors.Is(err, keys.ErrNotFound):
				fmt.Fprintf(env.Stdout, "No %s key was saved.\n", providerNames[p])
			case err != nil:
				return fmt.Errorf("could not delete the key from %s: %v", keys.Name(), err)
			default:
				fmt.Fprintf(env.Stdout, "Deleted the saved %s key.\n", providerNames[p])
			}
			return nil
		},
	}
}

// providerEnv looks up a provider's key: the environment first, then the key saved with watchdep keys.
func providerEnv(env *Env) func(string) string {
	return func(name string) string {
		if v := env.Getenv(name); v != "" {
			return v
		}
		for p, k := range codecheck.KeyEnv {
			if k == name && env.Keys != nil {
				if v, err := env.Keys.Get(p); err == nil {
					return v
				}
			}
		}
		return ""
	}
}

// prefsDir is where the assist preference is kept: beside the logins.
func prefsDir() string {
	p, err := client.CredentialsPath()
	if err != nil {
		return ""
	}
	return filepath.Dir(p)
}

// assistDefaults fills the provider and model check --assist uses from the preference saved in the
// keys menu, when neither flag names one and the preferred provider has a key.
func assistDefaults(env *Env, provider, model string) (string, string) {
	if provider != "" {
		return provider, model
	}
	prefs, err := keys.LoadPrefs(prefsDir())
	if err != nil || prefs.Provider == "" || providerEnv(env)(codecheck.KeyEnv[prefs.Provider]) == "" {
		return provider, model
	}
	if model == "" {
		model = prefs.Model
	}
	return prefs.Provider, model
}
