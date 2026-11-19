package cli

import (
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/kimathinjoki/watchdep-cli/internal/version"
)

// The reference: the whole command line as JSON, read by the public site's generator so the docs come
// from the same definitions as --help.

// ExitCodes says what each exit code means.
var ExitCodes = []RefExit{
	{ExitOK, "Nothing meets the threshold, and everything was looked at."},
	{ExitFindings, "A finding meets the threshold (gate), or the server answered with findings that fail."},
	{ExitIncomplete, "Incomplete: a file could not be read, an ecosystem is not supported, an image could not be pulled, or a source or the server did not answer or would not look (the plan's scans for today are used)."},
	{ExitUsage, "The command line or watchdep.yml is wrong."},
}

// EnvVars are the environment variables the CLI reads. A test checks that every one the code reads
// is listed.
var EnvVars = []RefEnv{
	{"WATCHDEP_SERVER", "scan, check, fix, deployed", "The watchdep server's address, instead of --server or a login."},
	{"WATCHDEP_TOKEN", "scan, check, fix, deployed", "The part's project token, instead of --token or a login."},
	{"ACCESSIBLE", "the menus (watchdep and watchdep keys on their own)", "Set it to ask each menu question as a plain numbered prompt, for a screen reader, instead of with the arrow keys."},
	{"CI", "scan", "Set by most CI services: scan then only sends, without waiting for the server's findings, unless --wait is given."},
	{"WATCHDEP_CREDENTIALS", "login and every command that talks to a server", "Where login stores each folder's token; by default the user's config folder."},
	{"GITHUB_TOKEN", "fix", "The repository's token, to open and update pull requests."},
	{"GITHUB_REPOSITORY", "fix", "The repository as owner/name (set by GitHub Actions)."},
	{"GITHUB_API_URL", "fix", "GitHub's API address; https://api.github.com by default (set by GitHub Actions)."},
	{"GITHUB_SHA", "deployed", "The commit, when --sha is not given (set by GitHub Actions)."},
	{"ANTHROPIC_API_KEY", "check --assist", "Your own Anthropic key for the assisted code check, used from this machine only."},
	{"NO_COLOR", "every command", "Any value turns colour off."},
	{"TERM", "every command", "dumb turns colour off."},
}

type RefExit struct {
	Code    int    `json:"code"`
	Meaning string `json:"meaning"`
}

type RefEnv struct {
	Name    string `json:"name"`
	UsedBy  string `json:"used_by"`
	Meaning string `json:"meaning"`
}

type RefFlag struct {
	Name      string `json:"name"`
	Shorthand string `json:"shorthand,omitempty"`
	Type      string `json:"type"`
	Default   string `json:"default"`
	Usage     string `json:"usage"`
	Global    bool   `json:"global"`
}

type RefCommand struct {
	Name     string       `json:"name"`
	Path     string       `json:"path"`
	Usage    string       `json:"usage"`
	Short    string       `json:"short"`
	Long     string       `json:"long"`
	Example  string       `json:"example,omitempty"`
	Flags    []RefFlag    `json:"flags"`
	Commands []RefCommand `json:"commands,omitempty"`
}

type Reference struct {
	Version   string     `json:"version"`
	Root      RefCommand `json:"root"`
	ExitCodes []RefExit  `json:"exit_codes"`
	Env       []RefEnv   `json:"env"`
}

func newReference(env *Env) *cobra.Command {
	return &cobra.Command{
		Use:    "reference",
		Short:  "Write the command line's reference as JSON (for the docs)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			return writeJSON(env.Stdout, BuildReference(c.Root()))
		},
	}
}

// BuildReference walks the visible commands.
func BuildReference(root *cobra.Command) Reference {
	return Reference{Version: version.Version, Root: refCommand(root), ExitCodes: ExitCodes, Env: EnvVars}
}

func refCommand(c *cobra.Command) RefCommand {
	rc := RefCommand{Name: c.Name(), Path: c.CommandPath(), Usage: c.UseLine(), Short: c.Short, Long: strings.TrimSpace(c.Long),
		Example: strings.TrimSpace(c.Example), Flags: []RefFlag{}}
	global := c.InheritedFlags()
	add := func(f *pflag.Flag, isGlobal bool) {
		if f.Hidden || f.Name == "help" {
			return
		}
		rc.Flags = append(rc.Flags, RefFlag{Name: f.Name, Shorthand: f.Shorthand, Type: f.Value.Type(), Default: f.DefValue, Usage: f.Usage, Global: isGlobal})
	}
	c.LocalFlags().VisitAll(func(f *pflag.Flag) { add(f, false) })
	global.VisitAll(func(f *pflag.Flag) { add(f, true) })
	if !c.HasParent() {
		for i := range rc.Flags {
			rc.Flags[i].Global = true
		}
	}
	sort.SliceStable(rc.Flags, func(i, j int) bool {
		if rc.Flags[i].Global != rc.Flags[j].Global {
			return !rc.Flags[i].Global
		}
		return rc.Flags[i].Name < rc.Flags[j].Name
	})
	for _, sub := range c.Commands() {
		if sub.Hidden || sub.Name() == "help" || !sub.IsAvailableCommand() {
			continue
		}
		rc.Commands = append(rc.Commands, refCommand(sub))
	}
	return rc
}
