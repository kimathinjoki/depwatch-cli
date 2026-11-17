package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kimathinjoki/watchdep-cli/internal/client"
	"github.com/kimathinjoki/watchdep-cli/internal/fix"
	"github.com/kimathinjoki/watchdep-cli/internal/image"
	"github.com/kimathinjoki/watchdep-cli/internal/version"
)

// fixTools lets tests replace the package managers and the registry.
var fixTools = fix.Tools{Run: fix.ExecRunner, Resolve: fix.RegistryDigest, ReadImage: image.ReadImage}

func newFix(env *Env) *cobra.Command {
	var server, token, base string
	var dryRun bool
	c := &cobra.Command{
		Use:   "fix [path]",
		Short: "Open a pull request per finding that the workspace wants fixed by pull request",
		Long: `Run in the project's own CI (watchdep-action does this). Fetches from the watchdep server the part's
findings whose fix setting is "open a pull request"; for each, makes a branch, upgrades the package
with the project's own package manager (an override for a package that comes in through another
one), takes the inventory again to check the fix version is reached, commits, pushes, and opens a pull
request with the repository's own token, or updates the one already open. Each run also reports the
state of the pull requests it opened before. watchdep never merges: a person approves and merges.

Needs GITHUB_TOKEN (contents and pull requests write) and GITHUB_REPOSITORY; GITHUB_API_URL for GitHub
Enterprise. --dry-run makes the changes, prints them and puts the files back, with no git and no
pull request.

Exit codes: 0 done; 2 the server did not answer, or a fix failed; 3 no token or a refused one.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			root, err := partRoot(args)
			if err != nil {
				return err
			}
			root, _ = filepath.Abs(root)
			srv, tok, err := resolveServer(env, server, token, root)
			if err != nil {
				return err
			}
			cl := &client.Client{Server: srv, Token: tok, UserAgent: version.UserAgent(), HTTP: env.HTTP}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
			defer cancel()
			var plan struct {
				Part             string     `json:"part"`
				ProductionBranch string     `json:"production_branch"`
				Fixes            []fix.Item `json:"fixes"`
			}
			if err := cl.GetFixes(ctx, &plan); err != nil {
				return serverError(env, c, err)
			}
			gh := fix.GitHub{API: orDefault(env.Getenv("GITHUB_API_URL"), "https://api.github.com"), Repo: env.Getenv("GITHUB_REPOSITORY"), Token: env.Getenv("GITHUB_TOKEN"), HTTP: env.HTTP}
			if !dryRun && (gh.Repo == "" || gh.Token == "") {
				return &usageError{msg: "watchdep fix opens pull requests with GITHUB_TOKEN and GITHUB_REPOSITORY (set in GitHub Actions); use --dry-run to only see the changes"}
			}
			git := fix.Git{Dir: root}
			if base == "" {
				base = plan.ProductionBranch
			}
			st := style{on: env.Color}
			failed := 0
			var report []map[string]any
			for _, item := range plan.Fixes {
				// A pull request already open: report its state, leave it as it is.
				if item.PullRequest != nil && !dryRun {
					pr, err := gh.Get(ctx, item.PullRequest.Number)
					if err == nil {
						if s := pr.WatchdepState(); s != item.PullRequest.State {
							_, _ = cl.PostJSON(ctx, "/api/v1/fix_pull_requests", map[string]any{"finding_id": item.FindingID, "number": pr.Number, "url": pr.URL,
								"branch": pr.Head.Ref, "base_branch": pr.Base.Ref, "state": s, "merged_at": pr.MergedAt})
						}
						if pr.WatchdepState() == "open" || pr.WatchdepState() == "merged" {
							fmt.Fprintf(env.Stdout, "%s  %s: pull request #%d is %s\n", st.bold(item.PrimaryID), item.Summary, pr.Number, pr.WatchdepState())
							report = append(report, map[string]any{"finding_id": item.FindingID, "pull_request": pr.Number, "state": pr.WatchdepState()})
							continue
						}
					}
				}
				branch := fix.BranchName(item, plan.Part)
				if !dryRun {
					if err := git.Branch(ctx, branch, base); err != nil {
						return err
					}
				}
				changes := map[string]fix.Change{}
				var notes []string
				var reached []fix.Target
				for _, t := range item.Targets {
					// What the server sent is checked before anything is read or changed.
					if err := fix.Check(root, &t); err != nil {
						notes = append(notes, fmt.Sprintf("%s %s: %v; the fix is named: upgrade to %s", t.Name, t.Version, err, t.Fix))
						continue
					}
					var snap fix.Snapshot
					dir := ""
					if t.Kind == "package" {
						dir = filepath.Join(root, filepath.FromSlash(filepath.Dir(t.SourceFile)))
						snap, _ = fix.TakeSnapshot(dir)
					}
					ch, err := fix.Apply(ctx, root, t, fixTools)
					if err == nil && t.Kind == "package" {
						err = fix.Verify(ctx, root, t)
					}
					if err != nil {
						if snap != nil {
							_ = snap.Restore(dir)
						}
						notes = append(notes, fmt.Sprintf("%s %s: %v; the fix is named: upgrade to %s", t.Name, t.Version, err, t.Fix))
						continue
					}
					changes[t.SourceFile+"|"+t.Name] = ch
					reached = append(reached, t)
					if dryRun {
						if snap != nil {
							_ = snap.Restore(dir)
						}
						ch.Undo()
					}
				}
				entry := map[string]any{"finding_id": item.FindingID, "primary_id": item.PrimaryID, "changes": changes, "named": notes}
				if len(reached) == 0 {
					failed++
					fmt.Fprintf(env.Stdout, "%s  %s\n", st.deepOrange(item.PrimaryID), strings.Join(notes, "; "))
					if !dryRun {
						_ = git.Checkout(ctx, base)
					}
					report = append(report, entry)
					continue
				}
				if dryRun {
					for _, t := range reached {
						ch := changes[t.SourceFile+"|"+t.Name]
						fmt.Fprintf(env.Stdout, "%s  would upgrade %s %s to %s: %s\n", st.bold(item.PrimaryID), t.Name, t.Version, t.Fix, ch.Words)
						if ch.Unverified != "" {
							fmt.Fprintf(env.Stdout, "    %s\n", st.deepOrange("not verified: "+ch.Unverified))
						}
					}
					report = append(report, entry)
					continue
				}
				first := reached[0]
				pushed, err := git.CommitAndPush(ctx, branch, fix.Title(item, first))
				if err != nil {
					_ = git.Checkout(ctx, base)
					return err
				}
				_ = git.Checkout(ctx, base)
				if !pushed {
					fmt.Fprintf(env.Stdout, "%s  nothing changed\n", item.PrimaryID)
					continue
				}
				pr, err := gh.Upsert(ctx, branch, base, fix.Title(item, first), fix.Body(item, plan.Part, changes))
				if err != nil {
					failed++
					fmt.Fprintf(env.Stdout, "%s  %s\n", st.deepOrange(item.PrimaryID), err)
					continue
				}
				_, err = cl.PostJSON(ctx, "/api/v1/fix_pull_requests", map[string]any{"finding_id": item.FindingID, "number": pr.Number, "url": pr.URL,
					"branch": branch, "base_branch": base, "state": "open", "strategy": changes[first.SourceFile+"|"+first.Name].Strategy, "target_version": first.Fix})
				if err != nil {
					return serverError(env, c, err)
				}
				entry["pull_request"] = pr.Number
				entry["url"] = pr.URL
				report = append(report, entry)
				fmt.Fprintf(env.Stdout, "%s  pull request #%d: %s\n", st.bold(item.PrimaryID), pr.Number, pr.URL)
			}
			if report == nil {
				report = []map[string]any{}
			}
			if jsonFlag(c) {
				_ = writeJSON(env.Stdout, map[string]any{"part": plan.Part, "fixes": report})
			} else if len(plan.Fixes) == 0 {
				fmt.Fprintf(env.Stdout, "No finding of %s is set to be fixed by pull request.\n", plan.Part)
			}
			if failed > 0 {
				return &exitError{code: ExitIncomplete}
			}
			return nil
		},
	}
	c.Flags().StringVar(&server, "server", "", "the watchdep server's address (default: WATCHDEP_SERVER, else the folder's login)")
	c.Flags().StringVar(&token, "token", "", "the part's token (default: WATCHDEP_TOKEN, else the folder's login)")
	c.Flags().StringVar(&base, "base", "", "the branch pull requests target (default: the part's production branch)")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "make the changes, print them and put the files back; no git, no pull request")
	return c
}

func newDeployed(env *Env) *cobra.Command {
	var server, token, sha, environment string
	c := &cobra.Command{
		Use:   "deployed --sha <commit>",
		Short: "Report that a commit was deployed, so production is what was deployed",
		Long: `Run in the deploy step after a deployment succeeds. With deployment reports, production is the last
deployed commit: a fix merged but not deployed is "fix merged, not yet in production" until then. Run
watchdep scan in the same step so the deployed commit has an inventory.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			if sha == "" {
				sha = env.Getenv("GITHUB_SHA")
			}
			if sha == "" {
				return &usageError{msg: "deployed needs --sha <commit> (or GITHUB_SHA)"}
			}
			srv, tok, err := resolveServer(env, server, token, ".")
			if err != nil {
				return err
			}
			cl := &client.Client{Server: srv, Token: tok, UserAgent: version.UserAgent(), HTTP: env.HTTP}
			out, err := cl.PostJSON(context.Background(), "/api/v1/deployments", map[string]any{"commit": sha, "environment": environment})
			if err != nil {
				return serverError(env, c, err)
			}
			if jsonFlag(c) {
				return writeJSON(env.Stdout, out)
			}
			fmt.Fprintf(env.Stdout, "Recorded the deployment of %s. Production is now the %v.\n", sha, out["production_rule"])
			if m, _ := out["message"].(string); m != "" {
				fmt.Fprintln(env.Stdout, style{on: env.Color}.deepOrange(m))
			}
			return nil
		},
	}
	c.Flags().StringVar(&server, "server", "", "the watchdep server's address")
	c.Flags().StringVar(&token, "token", "", "the part's token")
	c.Flags().StringVar(&sha, "sha", "", "the deployed commit (default: GITHUB_SHA)")
	c.Flags().StringVar(&environment, "environment", "production", "the environment deployed to")
	return c
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
