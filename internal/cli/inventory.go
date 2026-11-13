package cli

import (
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kimathinjoki/depwatch-cli/internal/collect"
	"github.com/kimathinjoki/depwatch-cli/internal/inventory"
	"github.com/kimathinjoki/depwatch-cli/internal/version"
)

type takeFlags struct {
	images []string
	rootfs []string
}

func addTakeFlags(c *cobra.Command, f *takeFlags) {
	c.Flags().StringArrayVar(&f.images, "image", nil, "read a container image: a local tarball (docker save, OCI archive) or a registry reference; repeatable")
	c.Flags().StringArrayVar(&f.rootfs, "rootfs", nil, "read the package databases in a folder laid out like a root filesystem; repeatable")
}

func newInventory(env *Env) *cobra.Command {
	var tf takeFlags
	var takenBy, commit, branch string
	var pull bool
	c := &cobra.Command{
		Use:   "inventory [path]",
		Short: "List everything the project contains, and everything that could not be read",
		Long: `List every package at every depth with its dependency paths and scope, the runtimes, the
operating system packages of any image or root filesystem given, and every file that could not be
read, every unsupported ecosystem and every manifest with no lockfile.

Makes no network call (unless --pull-images). Base images named in depwatch.yml or a Dockerfile are listed as not read;
depwatch gate pulls them, or pass --image.

Exit codes: 0 complete, 2 incomplete (something could not be read), 3 usage or depwatch.yml error.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			root := "."
			if len(args) == 1 {
				root = args[0]
			}
			if takenBy != "cli" && takenBy != "github" {
				return &usageError{msg: "--taken-by is cli or github"}
			}
			inv, _, err := collect.Take(context.Background(), collect.Options{
				Root: root, Images: tf.images, RootFS: tf.rootfs, PullImages: pull, CLIVersion: version.Version,
				TakenBy: takenBy, Commit: commit, Branch: branch,
			})
			if err != nil {
				return err
			}
			if jsonFlag(c) {
				if err := inv.Write(env.Stdout); err != nil {
					return err
				}
			} else {
				printInventory(env.Stdout, style{on: env.Color}, inv)
			}
			if !inv.Complete() {
				return &exitError{code: ExitIncomplete}
			}
			return nil
		},
	}
	addTakeFlags(c, &tf)
	c.Flags().BoolVar(&pull, "pull-images", false, "pull the base images named in Dockerfiles and depwatch.yml (makes network calls)")
	c.Flags().StringVar(&takenBy, "taken-by", "cli", "how the files were obtained: cli, or github when a server fetched them")
	c.Flags().StringVar(&commit, "commit", "", "the commit the files are from, for a folder that is not a git checkout")
	c.Flags().StringVar(&branch, "branch", "", "the branch the files are from, for a folder that is not a git checkout")
	for _, f := range []string{"taken-by", "commit", "branch"} {
		_ = c.Flags().MarkHidden(f)
	}
	return c
}

func partLine(inv *inventory.Inventory) string {
	s := inv.Part.Root
	if inv.Part.Branch != "" || inv.Part.Commit != "" {
		commit := inv.Part.Commit
		if len(commit) > 7 {
			commit = commit[:7]
		}
		s += "  " + strings.TrimSpace(inv.Part.Branch+" "+commit)
	}
	return s
}

func printInventory(w io.Writer, st style, inv *inventory.Inventory) {
	fmt.Fprintf(w, "%s  %s\n\n", st.bold("depwatch inventory"), partLine(inv))

	// What was not read comes first, in deep orange: it is never read as clean.
	printGaps(w, st, inv)

	// Packages by part folder and ecosystem.
	type groupKey struct{ dir, eco, file string }
	counts := map[groupKey][3]int{} // total, production, development
	var keys []groupKey
	for _, p := range inv.Packages {
		k := groupKey{dir: path.Dir(p.SourceFile), eco: p.Ecosystem, file: path.Base(p.SourceFile)}
		c, ok := counts[k]
		if !ok {
			keys = append(keys, k)
		}
		c[0]++
		if p.Scope == inventory.ScopeProduction {
			c[1]++
		} else {
			c[2]++
		}
		counts[k] = c
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].dir != keys[j].dir {
			return keys[i].dir < keys[j].dir
		}
		return keys[i].eco < keys[j].eco
	})
	if len(keys) > 0 {
		fmt.Fprintln(w, st.bold("Packages"))
		for _, k := range keys {
			c := counts[k]
			dir := k.dir
			if dir == "." {
				dir = inv.Part.Root
			}
			fmt.Fprintf(w, "  %-28s %-10s %-22s %4d  (%d production, %d development)\n", dir, k.eco, k.file, c[0], c[1], c[2])
		}
		fmt.Fprintln(w)
	}
	if len(inv.OSPackages) > 0 {
		fmt.Fprintln(w, st.bold("Operating system packages"))
		type osKey struct{ where, eco string }
		oc := map[osKey]int{}
		var oks []osKey
		for _, p := range inv.OSPackages {
			where := p.SourceFile
			if p.Image != "" {
				where = p.Image
			}
			k := osKey{where, p.Ecosystem}
			if _, ok := oc[k]; !ok {
				oks = append(oks, k)
			}
			oc[k]++
		}
		for _, k := range oks {
			fmt.Fprintf(w, "  %-40s %-16s %4d\n", k.where, k.eco, oc[k])
		}
		fmt.Fprintln(w)
	}
	if len(inv.Runtimes) > 0 {
		fmt.Fprintln(w, st.bold("Runtimes")+st.gray("  (listed, not yet checked)"))
		for _, r := range inv.Runtimes {
			fmt.Fprintf(w, "  %-10s %-14s %-9s %s\n", r.Name, r.Version, r.Kind, r.SourceFile)
		}
		fmt.Fprintln(w)
	}
	if len(inv.Conflicts) > 0 {
		fmt.Fprintln(w, st.deepOrange("Runtime versions disagree"))
		for _, c := range inv.Conflicts {
			var parts []string
			for _, r := range c.Runtimes {
				parts = append(parts, r.Version+" in "+r.SourceFile)
			}
			fmt.Fprintf(w, "  %s: %s\n", c.Name, strings.Join(parts, ", "))
		}
		fmt.Fprintln(w)
	}
	if len(inv.Packages) == 0 && len(inv.OSPackages) == 0 && len(inv.FilesNotRead) == 0 && len(inv.Unsupported) == 0 {
		fmt.Fprintln(w, st.deepOrange("No dependency files found in this folder.")+" Nothing was checked; this is not a clean result.")
		fmt.Fprintln(w)
	}
	total := len(inv.Packages) + len(inv.OSPackages)
	fmt.Fprintf(w, "%d packages from %d files.", total, len(inv.FilesRead))
	if inv.Complete() {
		fmt.Fprintln(w, " Everything found was read.")
	} else {
		fmt.Fprintln(w, " "+st.deepOrange("Incomplete: some of what was found could not be read."))
	}
}

func printGaps(w io.Writer, st style, inv *inventory.Inventory) {
	if len(inv.FilesNotRead) > 0 {
		fmt.Fprintln(w, st.deepOrange(fmt.Sprintf("Not read (%d)", len(inv.FilesNotRead))))
		for _, f := range inv.FilesNotRead {
			fmt.Fprintf(w, "  %s\n    %s\n", f.Path, f.Reason)
		}
		fmt.Fprintln(w)
	}
	if len(inv.Unsupported) > 0 {
		fmt.Fprintln(w, st.deepOrange(fmt.Sprintf("Unsupported ecosystems (%d)", len(inv.Unsupported))))
		for _, u := range inv.Unsupported {
			fmt.Fprintf(w, "  %-40s %s\n", u.Path, u.Ecosystem)
		}
		fmt.Fprintln(w)
	}
	var unread []inventory.Image
	for _, img := range inv.Images {
		if !img.Read {
			unread = append(unread, img)
		}
	}
	if len(unread) > 0 {
		fmt.Fprintln(w, st.deepOrange(fmt.Sprintf("Images not read (%d)", len(unread))))
		for _, img := range unread {
			fmt.Fprintf(w, "  %s\n    %s\n", img.Reference, img.Reason)
		}
		fmt.Fprintln(w)
	}
	if len(inv.Unpinned) > 0 {
		fmt.Fprintln(w, st.deepOrange(fmt.Sprintf("No lockfile, ranges only, not checked in this version (%d)", len(inv.Unpinned))))
		for _, u := range inv.Unpinned {
			n := 0
			for _, p := range inv.Packages {
				if p.SourceFile == u.Path && p.Version == "" {
					n++
				}
			}
			fmt.Fprintf(w, "  %-40s %s, %d packages with ranges only\n", u.Path, u.Ecosystem, n)
		}
		fmt.Fprintln(w)
	}
}
