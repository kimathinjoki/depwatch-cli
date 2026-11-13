package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/kimathinjoki/depwatch-cli/internal/inventory"
	"github.com/kimathinjoki/depwatch-cli/internal/match"
	"github.com/kimathinjoki/depwatch-cli/internal/mirror"
	"github.com/kimathinjoki/depwatch-cli/internal/sources"
	"github.com/kimathinjoki/depwatch-cli/internal/version"
)

func newMirror(env *Env) *cobra.Command {
	c := &cobra.Command{
		Use:   "mirror",
		Short: "Keep a local copy of OSV for matching with no network",
	}
	var dir string
	var ecos []string
	var baseURL, archive string
	sync := &cobra.Command{
		Use:   "sync --dir <dir> --ecosystem <name>...",
		Short: "Download OSV's export for each ecosystem when it changed, and index it",
		Long: `Download OSV's export for each named ecosystem (npm, PyPI, RubyGems, Debian and so on; the part
before any ":"), keep the archive and index it by package. An unchanged export is not downloaded again.
A failed download keeps the previous copy and is reported. With --archive, an export already
downloaded (for a copy with no route to OSV) is installed instead, for one ecosystem.

Exit codes: 0 every ecosystem synced; 2 at least one did not.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if dir == "" || len(ecos) == 0 {
				return &usageError{msg: "mirror sync needs --dir and at least one --ecosystem"}
			}
			s := &mirror.Syncer{Dir: dir, BaseURL: baseURL, UserAgent: version.UserAgent()}
			if env.HTTP != nil {
				s.Client = env.HTTP
			}
			var states []mirror.State
			failed := false
			if archive != "" && len(ecos) != 1 {
				return &usageError{msg: "--archive installs one ecosystem's export: give exactly one --ecosystem"}
			}
			for _, e := range ecos {
				var st mirror.State
				var err error
				if archive != "" {
					st, err = s.Import(e, archive)
				} else {
					st, err = s.Sync(context.Background(), e)
				}
				if err != nil {
					failed = true
				}
				states = append(states, st)
			}
			if jsonFlag(c) {
				if err := writeJSON(env.Stdout, map[string]any{"ecosystems": states}); err != nil {
					return err
				}
			} else {
				st := style{on: env.Color}
				for _, s := range states {
					if s.LastError != "" {
						fmt.Fprintf(env.Stdout, "%s  %s\n", st.deepOrange(s.Ecosystem), s.LastError)
						continue
					}
					fmt.Fprintf(env.Stdout, "%s  %d entries, synced %s\n", s.Ecosystem, s.Entries, s.SyncedAt)
				}
			}
			if failed {
				return &exitError{code: ExitIncomplete}
			}
			return nil
		},
	}
	sync.Flags().StringVar(&dir, "dir", "", "the mirror folder")
	sync.Flags().StringArrayVar(&ecos, "ecosystem", nil, "an OSV ecosystem to sync; repeatable")
	sync.Flags().StringVar(&archive, "archive", "", "install this downloaded export (all.zip) instead of downloading")
	sync.Flags().StringVar(&baseURL, "base-url", mirror.DefaultBaseURL, "where OSV publishes its exports")
	_ = sync.Flags().MarkHidden("base-url")

	var statusDir string
	status := &cobra.Command{
		Use:   "status --dir <dir>",
		Short: "Show what the mirror holds and when each ecosystem last synced",
		Args:  cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if statusDir == "" {
				return &usageError{msg: "mirror status needs --dir"}
			}
			states, err := mirror.States(statusDir)
			if err != nil {
				return err
			}
			if states == nil {
				states = []mirror.State{}
			}
			if jsonFlag(c) {
				return writeJSON(env.Stdout, map[string]any{"ecosystems": states})
			}
			if len(states) == 0 {
				fmt.Fprintln(env.Stdout, "The mirror holds nothing yet.")
			}
			for _, s := range states {
				line := fmt.Sprintf("%-12s %7d entries  last good sync %s", s.Ecosystem, s.Entries, orNever(s.SyncedAt))
				if s.LastError != "" {
					line += "  last attempt failed: " + s.LastError
				}
				fmt.Fprintln(env.Stdout, line)
			}
			return nil
		},
	}
	status.Flags().StringVar(&statusDir, "dir", "", "the mirror folder")
	c.AddCommand(sync, status)
	return c
}

func orNever(s string) string {
	if s == "" {
		return "never"
	}
	return s
}

func newMatch(env *Env) *cobra.Command {
	var mirrorDir, invPath string
	c := &cobra.Command{
		Use:   "match --mirror <dir> --inventory <file>",
		Short: "Answer which advisories affect each package of an inventory, from a local mirror",
		Long: `Read an inventory file (as depwatch inventory --json writes it) and answer, from a local OSV
mirror and with no network, which advisories affect each package and OS package. The answer holds
every advisory's entry and everything that was not checked. It does no ranking. The depwatch server
uses this command, so the CLI and the server match versions with the same rules.

Exit codes: 0 complete; 2 incomplete (an ecosystem the mirror does not hold, an unreadable mirror);
3 usage, or an unreadable inventory.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if mirrorDir == "" || invPath == "" {
				return &usageError{msg: "match needs --mirror and --inventory"}
			}
			f, err := os.Open(invPath)
			if err != nil {
				return &usageError{msg: err.Error()}
			}
			defer f.Close()
			inv, err := inventory.Read(f)
			if err != nil {
				return &usageError{msg: err.Error()}
			}
			osv := sources.NewMirrorOSV(mirrorDir)
			defer osv.R.Close()
			res := match.Lookup(context.Background(), inv, osv, 8)
			if jsonFlag(c) {
				if err := writeJSON(env.Stdout, res); err != nil {
					return err
				}
			} else {
				fmt.Fprintf(env.Stdout, "%d packages checked, %d affected, %d advisories.\n", res.Checked, len(res.Matches), len(res.Advisories))
				for _, n := range res.NotChecked {
					fmt.Fprintf(env.Stdout, "Not checked: %s: %s\n", n.What, n.Why)
				}
			}
			if !res.Complete {
				return &exitError{code: ExitIncomplete}
			}
			return nil
		},
	}
	c.Flags().StringVar(&mirrorDir, "mirror", "", "the mirror folder")
	c.Flags().StringVar(&invPath, "inventory", "", "an inventory file")
	return c
}

// mirrorSources answers OSV from a mirror and KEV and EPSS live.
func mirrorSources(dir string) sources.Set {
	live := sources.Live(version.UserAgent(), 60*time.Second)
	osv := sources.NewMirrorOSV(dir)
	osv.MaxAge = sources.StaleAfter
	live.OSV = osv
	return live
}
