// Package cli is the watchdep command line: its commands, flags, output and exit codes.
package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/kimathinjoki/watchdep-cli/internal/config"
	"github.com/kimathinjoki/watchdep-cli/internal/sources"
	"github.com/kimathinjoki/watchdep-cli/internal/version"
)

// Exit codes.
const (
	ExitOK         = 0
	ExitFindings   = 1
	ExitIncomplete = 2
	ExitUsage      = 3
)

// Env is what a run depends on outside its arguments. Tests replace parts of it.
type Env struct {
	Stdout, Stderr io.Writer
	// Color is true when the output is a terminal and NO_COLOR is not set.
	Color bool
	// Sources builds the advisory sources; nil means the live ones.
	Sources func() (sources.Set, error)
	Getenv  func(string) string
	// HTTP, when set, is used for calls to a watchdep server and to OSV's exports.
	HTTP *http.Client
	// Stdin feeds commands that read a listing.
	Stdin io.Reader
}

// usageError is a problem with the command line or watchdep.yml.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// exitError carries an exit code out of a command after its output is written.
type exitError struct{ code int }

func (e *exitError) Error() string { return fmt.Sprintf("exit %d", e.code) }

// Main runs the command line with the real environment.
func Main(args []string, stdout, stderr io.Writer) int {
	color := false
	if f, ok := stdout.(*os.File); ok && term.IsTerminal(int(f.Fd())) && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb" {
		color = true
	}
	return Run(args, Env{Stdout: stdout, Stderr: stderr, Color: color, Getenv: os.Getenv, Stdin: os.Stdin})
}

// Run runs the command line and returns the exit code.
func Run(args []string, env Env) int {
	if env.Getenv == nil {
		env.Getenv = func(string) string { return "" }
	}
	root := newRoot(&env)
	root.SetArgs(args)
	root.SetOut(env.Stdout)
	root.SetErr(env.Stderr)
	if env.Stdin != nil {
		root.SetIn(env.Stdin)
	}
	err := root.Execute()
	if err == nil {
		return ExitOK
	}
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	jsonOut := hasJSONFlag(args)
	var ue *usageError
	var ce *config.Error
	msg := err.Error()
	switch {
	case errors.As(err, &ce):
		msg = ce.Error()
	case errors.As(err, &ue):
	default:
		// cobra's own errors (unknown command or flag, bad argument) are usage errors too.
		if !isCobraUsage(err) {
			writeError(env, jsonOut, msg)
			return ExitIncomplete
		}
		if !jsonOut {
			fmt.Fprintln(env.Stderr, root.UsageString())
		}
	}
	writeError(env, jsonOut, msg)
	return ExitUsage
}

// partRoot is the folder a command reads: the path given, or the current folder. A path that does
// not exist, or is not a folder, is a usage error naming the path as given.
func partRoot(args []string) (string, error) {
	root := "."
	if len(args) == 1 {
		root = args[0]
	}
	st, err := os.Stat(root)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "", &usageError{msg: fmt.Sprintf("the path %q does not exist", root)}
	case err != nil:
		return "", &usageError{msg: fmt.Sprintf("the path %q cannot be read: %v", root, err)}
	case !st.IsDir():
		return "", &usageError{msg: fmt.Sprintf("the path %q is not a folder", root)}
	}
	return root, nil
}

func writeError(env Env, jsonOut bool, msg string) {
	if jsonOut {
		enc := json.NewEncoder(env.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]string{"error": msg})
		return
	}
	fmt.Fprintln(env.Stderr, "watchdep: "+msg)
}

func hasJSONFlag(args []string) bool {
	for _, a := range args {
		if a == "--json" || a == "--json=true" {
			return true
		}
		if a == "--" {
			break
		}
	}
	return false
}

func isCobraUsage(err error) bool {
	m := err.Error()
	for _, s := range []string{"unknown command", "unknown flag", "unknown shorthand flag", "flag needs an argument",
		"invalid argument", "accepts at most", "accepts ", "requires at least", "bad flag syntax"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

func newRoot(env *Env) *cobra.Command {
	root := &cobra.Command{
		Use:   "watchdep",
		Short: "Watch every layer of a project's dependencies for known vulnerabilities and compromised releases",
		Long: `watchdep takes the inventory of a project (every package at every depth, runtimes, and the
operating system packages of its images) and checks it for known vulnerabilities and compromised
releases.

Nothing reads as clean when watchdep did not look: a file it could not read, an ecosystem it does
not support, an image it could not pull or a source that did not answer is shown, and makes the
run incomplete.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.PersistentFlags().Bool("json", false, "write all output as JSON")
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error { return err })
	root.AddCommand(newVersion(env), newInventory(env), newGate(env), newScan(env), newLogin(env), newMirror(env), newMatch(env), newWanted(env), newCheck(env), newModels(env), newFix(env), newDeployed(env), newReference(env))
	root.CompletionOptions.DisableDefaultCmd = true
	return root
}

func jsonFlag(c *cobra.Command) bool {
	v, _ := c.Flags().GetBool("json")
	return v
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

func newVersion(env *Env) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version, commit and build date",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if jsonFlag(c) {
				return writeJSON(env.Stdout, map[string]string{"version": version.Version, "commit": version.Commit, "date": version.Date})
			}
			fmt.Fprintf(env.Stdout, "watchdep %s (commit %s, built %s)\n", version.Version, version.Commit, version.Date)
			return nil
		},
	}
}
