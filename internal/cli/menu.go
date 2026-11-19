package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"golang.org/x/term"

	"github.com/kimathinjoki/watchdep-cli/internal/codecheck"
	"github.com/kimathinjoki/watchdep-cli/internal/keys"
)

// The menus: watchdep on its own, and watchdep keys on its own, in a terminal. Each choice runs the
// same command a person would type, so the menu never does anything the commands do not. Arrow keys
// choose; with ACCESSIBLE set (or in tests) each question is a plain numbered prompt instead.

// errQuit leaves a menu without an error.
var errQuit = errors.New("quit")

// lineReader gives the plain prompts one line per read. Each prompt reads through its own buffered
// scanner, which would otherwise take the answers meant for the next ones.
type lineReader struct {
	r *bufio.Reader
}

func (l *lineReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		b, err := l.r.ReadByte()
		if err != nil {
			if n == 0 {
				return 0, err
			}
			break
		}
		p[n] = b
		n++
		if b == '\n' {
			break
		}
	}
	return n, nil
}

// done is true when nothing is left to answer with: the menu then quits rather than ask again.
func (l *lineReader) done() bool {
	_, err := l.r.Peek(1)
	return err != nil
}

// ttyLineReader is a lineReader on a terminal: a plain password prompt reads the terminal itself.
type ttyLineReader struct {
	*lineReader
	f *os.File
}

func (t ttyLineReader) Fd() uintptr { return t.f.Fd() }

func (env *Env) prompts() *lineReader {
	switch r := env.Stdin.(type) {
	case *lineReader:
		return r
	case ttyLineReader:
		return r.lineReader
	}
	l := &lineReader{r: bufio.NewReader(env.Stdin)}
	if f, ok := env.Stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		env.Stdin = ttyLineReader{lineReader: l, f: f}
	} else {
		env.Stdin = l
	}
	return l
}

func (env *Env) ask(fields ...huh.Field) error {
	f := huh.NewForm(huh.NewGroup(fields...)).WithAccessible(env.Accessible).WithShowHelp(!env.Accessible)
	if env.Accessible {
		if env.prompts().done() {
			return errQuit
		}
		f = f.WithInput(env.Stdin).WithOutput(env.Stdout)
	}
	err := f.Run()
	if errors.Is(err, huh.ErrUserAborted) {
		return errQuit
	}
	return err
}

// secret is a field for a key or token: hidden, except as a plain prompt with no terminal to hide it
// on (piped answers), where nothing is shown anyway.
func (env *Env) secret(title string, value *string) *huh.Input {
	in := huh.NewInput().Title(title).Value(value).Validate(func(s string) error {
		if strings.TrimSpace(s) == "" {
			return errors.New("paste it, or press Ctrl-C to go back")
		}
		return nil
	})
	if env.Accessible {
		env.prompts()
		if _, ok := env.Stdin.(ttyLineReader); !ok {
			return in
		}
	}
	return in.EchoMode(huh.EchoModePassword)
}

// sub runs one of watchdep's own commands as if it had been typed, and says if it did not succeed.
func (env *Env) sub(args ...string) {
	fmt.Fprintf(env.Stdout, "\n$ watchdep %s\n", strings.Join(args, " "))
	if code := Run(args, *env); code != ExitOK {
		fmt.Fprintf(env.Stdout, "(exit %d)\n", code)
	}
	fmt.Fprintln(env.Stdout)
}

func runMenu(env *Env) error {
	dir, _ := os.Getwd()
	fmt.Fprintf(env.Stdout, "watchdep, in %s\n", dir)
	for {
		var choice string
		err := env.ask(huh.NewSelect[string]().Title("What do you want to do?").Options(
			huh.NewOption("Check this folder now (no account needed)", "gate"),
			huh.NewOption("Send this folder to watchdep, and see its findings", "scan"),
			huh.NewOption("Log in this folder with a part's token", "login"),
			huh.NewOption("Check whether the code uses the vulnerable packages", "check"),
			huh.NewOption("Set up AI keys", "keys"),
			huh.NewOption("List what this folder contains", "inventory"),
			huh.NewOption("Quit", "quit"),
		).Value(&choice))
		if errors.Is(err, errQuit) || choice == "quit" {
			return nil
		}
		if err != nil {
			return err
		}
		switch choice {
		case "gate", "inventory":
			env.sub(choice)
		case "scan":
			ok, err := ensureLogin(env)
			if err != nil && !errors.Is(err, errQuit) {
				return err
			}
			if ok {
				env.sub("scan")
			}
		case "login":
			if err := loginMenu(env); err != nil && !errors.Is(err, errQuit) {
				return err
			}
		case "check":
			if err := checkMenu(env); err != nil && !errors.Is(err, errQuit) {
				return err
			}
		case "keys":
			if err := keysMenu(env); err != nil && !errors.Is(err, errQuit) {
				return err
			}
		}
	}
}

// ensureLogin offers to log in when this folder has no server and token yet.
func ensureLogin(env *Env) (bool, error) {
	if _, _, err := resolveServer(env, "", "", "."); err == nil {
		return true, nil
	}
	login := true
	if err := env.ask(huh.NewConfirm().Title("This folder has no login yet. Log in with a part's token now?").Value(&login)); err != nil {
		return false, err
	}
	if !login {
		return false, nil
	}
	if err := loginMenu(env); err != nil {
		return false, err
	}
	_, _, err := resolveServer(env, "", "", ".")
	return err == nil, nil
}

func loginMenu(env *Env) error {
	server := env.Getenv("WATCHDEP_SERVER")
	if server == "" {
		server = "https://app.watchdep.com"
	}
	var token string
	err := env.ask(
		huh.NewInput().Title("Server").Value(&server),
		env.secret("The part's token (from its Tokens page; it is not shown)", &token),
	)
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout)
	if code := Run([]string{"login", "--server", strings.TrimSpace(server), "--token", strings.TrimSpace(token)}, *env); code != ExitOK {
		fmt.Fprintf(env.Stdout, "(exit %d)\n", code)
	}
	fmt.Fprintln(env.Stdout)
	return nil
}

func checkMenu(env *Env) error {
	if ok, err := ensureLogin(env); err != nil || !ok {
		return err
	}
	how := "search"
	if err := env.ask(huh.NewSelect[string]().Title("How?").Options(
		huh.NewOption("Search the code (nothing leaves this machine but file paths and line numbers)", "search"),
		huh.NewOption("Search, and have an AI model draft each verdict with your own key", "assist"),
	).Value(&how)); err != nil {
		return err
	}
	if how == "assist" && !anyKey(env) {
		fmt.Fprintln(env.Stdout, "No AI key is set up yet.")
		if err := setUpProvider(env); err != nil {
			return err
		}
		if !anyKey(env) {
			return nil
		}
	}
	if how == "assist" {
		env.sub("check", "--assist")
	} else {
		env.sub("check")
	}
	return nil
}

func anyKey(env *Env) bool {
	get := providerEnv(env)
	for _, p := range codecheck.Providers {
		if get(codecheck.KeyEnv[p]) != "" {
			return true
		}
	}
	return false
}

// keyStatus is where a provider's key comes from, for the menus: "saved", "from ANTHROPIC_API_KEY" or "".
func keyStatus(env *Env, p string) string {
	if env.Getenv(codecheck.KeyEnv[p]) != "" {
		return "from " + codecheck.KeyEnv[p]
	}
	if _, err := env.Keys.Get(p); err == nil {
		return "saved"
	}
	return ""
}

func keysMenu(env *Env) error {
	for {
		var choice string
		if err := env.ask(huh.NewSelect[string]().Title("AI keys").Options(
			huh.NewOption("Set up a provider: key, then model", "set"),
			huh.NewOption("Remove a saved key", "remove"),
			huh.NewOption("See what is set up", "list"),
			huh.NewOption("Back", "back"),
		).Value(&choice)); err != nil {
			return err
		}
		switch choice {
		case "back":
			return nil
		case "list":
			env.sub("keys", "list")
			if prefs, err := keys.LoadPrefs(prefsDir()); err == nil && prefs.Provider != "" {
				fmt.Fprintf(env.Stdout, "check --assist uses %s, %s, unless you name another.\n\n", providerNames[prefs.Provider], prefs.Model)
			}
		case "remove":
			var p string
			opts := []huh.Option[string]{}
			for _, name := range codecheck.Providers {
				if _, err := env.Keys.Get(name); err == nil {
					opts = append(opts, huh.NewOption(providerNames[name], name))
				}
			}
			if len(opts) == 0 {
				fmt.Fprintln(env.Stdout, "No key is saved.")
				fmt.Fprintln(env.Stdout)
				continue
			}
			if err := env.ask(huh.NewSelect[string]().Title("Remove which key?").Options(opts...).Value(&p)); err != nil {
				return err
			}
			env.sub("keys", "remove", p)
		case "set":
			if err := setUpProvider(env); err != nil {
				return err
			}
		}
	}
}

// setUpProvider walks through one provider: choose it, give or keep its key, check the key by
// listing the provider's models, choose a model, and whether check --assist uses them by default.
func setUpProvider(env *Env) error {
	var p string
	opts := []huh.Option[string]{}
	for _, name := range codecheck.Providers {
		label := providerNames[name]
		if s := keyStatus(env, name); s != "" {
			label += "  (" + s + ")"
		}
		opts = append(opts, huh.NewOption(label, name))
	}
	if err := env.ask(huh.NewSelect[string]().Title("Which provider?").Options(opts...).Value(&p)); err != nil {
		return err
	}

	key := providerEnv(env)(codecheck.KeyEnv[p])
	replace := key == ""
	if key != "" && keyStatus(env, p) == "saved" {
		if err := env.ask(huh.NewConfirm().Title("A key is saved for " + providerNames[p] + ". Replace it?").Value(&replace)); err != nil {
			return err
		}
	}
	if replace {
		var typed string
		if err := env.ask(env.secret("Paste your "+providerNames[p]+" API key (it is not shown)", &typed)); err != nil {
			return err
		}
		key = strings.TrimSpace(typed)
	}

	fmt.Fprintf(env.Stdout, "Checking the key with %s...\n", providerNames[p])
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	prov, err := codecheck.NewProvider(ctx, p, env.AssistURL, func(name string) string {
		if name == codecheck.KeyEnv[p] {
			return key
		}
		return ""
	})
	var models []string
	if err == nil {
		models, err = prov.Models(ctx)
	}
	if err != nil {
		fmt.Fprintf(env.Stdout, "%s did not accept the key: %v\nNothing was saved.\n\n", providerNames[p], err)
		return nil
	}
	fmt.Fprintf(env.Stdout, "The key works: %d models available.\n", len(models))
	if replace {
		if err := env.Keys.Set(p, key); err != nil {
			fmt.Fprintf(env.Stdout, "Could not save it in %s (%v): set %s in the environment instead.\n\n", keys.Name(), err, codecheck.KeyEnv[p])
			return nil
		}
		fmt.Fprintf(env.Stdout, "Saved in %s.\n", keys.Name())
	}

	model := codecheck.DefaultModels[p]
	if len(models) > 0 {
		mopts := []huh.Option[string]{}
		for _, m := range models {
			label := m
			if m == codecheck.DefaultModels[p] {
				label += "  (watchdep's default)"
			}
			mopts = append(mopts, huh.NewOption(label, m))
		}
		if model == "" || !contains(models, model) {
			model = models[0]
		}
		if err := env.ask(huh.NewSelect[string]().Title("Which model?").Options(mopts...).Value(&model)); err != nil {
			return err
		}
	}
	useDefault := true
	if err := env.ask(huh.NewConfirm().Title(fmt.Sprintf("Use %s, %s for check --assist by default?", providerNames[p], model)).Value(&useDefault)); err != nil {
		return err
	}
	if useDefault {
		if err := keys.SavePrefs(prefsDir(), keys.Prefs{Provider: p, Model: model}); err != nil {
			return err
		}
		fmt.Fprintf(env.Stdout, "Done. watchdep check --assist now uses %s, %s.\n\n", providerNames[p], model)
	} else {
		fmt.Fprintf(env.Stdout, "Done. Use it with: watchdep check --assist --provider %s --model %s\n\n", p, model)
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
