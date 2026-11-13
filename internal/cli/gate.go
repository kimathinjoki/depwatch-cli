package cli

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/kimathinjoki/depwatch-cli/internal/collect"
	"github.com/kimathinjoki/depwatch-cli/internal/inventory"
	"github.com/kimathinjoki/depwatch-cli/internal/match"
	"github.com/kimathinjoki/depwatch-cli/internal/rank"
	"github.com/kimathinjoki/depwatch-cli/internal/sources"
	"github.com/kimathinjoki/depwatch-cli/internal/version"
)

// nothingFoundWhy is the reason given when a folder holds no dependency files at all.
const nothingFoundWhy = "no dependency files found: nothing was checked (is the code checked out here?)"

// Thresholds --fail-on accepts.
var thresholds = map[string]string{
	"malicious": "a malicious release, in any scope (its install scripts already ran)",
	"kev":       "listed in CISA KEV (exploited now), in production scope",
	"severe":    "at level severe, provisional included",
	"high":      "at level high or severe",
}

// GateResult is the JSON gate writes.
type GateResult struct {
	SchemaVersion   string             `json:"schema_version"`
	CLIVersion      string             `json:"cli_version"`
	Part            inventory.Part     `json:"part"`
	FailOn          []string           `json:"fail_on"`
	ExitCode        int                `json:"exit_code"`
	Complete        bool               `json:"complete"`
	MeetThreshold   []string           `json:"meet_threshold"`
	Findings        []match.Finding    `json:"findings"`
	NotChecked      []match.NotChecked `json:"not_checked"`
	SourceErrors    []string           `json:"source_errors"`
	PackagesChecked int                `json:"packages_checked"`
}

func newGate(env *Env) *cobra.Command {
	var tf takeFlags
	var failOn []string
	var allowIncomplete bool
	var threshold float64
	var recording string
	var mirrorDir string
	c := &cobra.Command{
		Use:   "gate [path]",
		Short: "Check the project against OSV, CISA KEV and EPSS, and fail the build on a finding",
		Long: `Take the inventory, check it against OSV, CISA KEV and EPSS with no depwatch server, rank
every finding, and exit non-zero when one meets the threshold, so a CI build can stop on it.

--fail-on takes any of:
  malicious  a malicious release, in any scope (its install scripts already ran)
  kev        listed in CISA KEV (exploited now), in production scope
  severe     at level severe, provisional included
  high       at level high or severe

Exit codes:
  0  nothing meets the threshold and the check is complete
  1  a finding meets the threshold (wins over incomplete)
  2  the check is incomplete: something could not be read or checked, or a source did not answer
     (0 instead with --allow-incomplete, when nothing meets the threshold)
  3  a usage or depwatch.yml error`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			root, err := partRoot(args)
			if err != nil {
				return err
			}
			fail, err := parseFailOn(failOn)
			if err != nil {
				return err
			}
			if threshold <= 0 || threshold > 1 {
				return &usageError{msg: "--epss-threshold must be above 0 and at most 1 (0.10 is 10 percent)"}
			}
			src, err := gateSources(env, recording)
			if mirrorDir != "" && recording == "" {
				src = mirrorSources(mirrorDir)
			}
			if err != nil {
				return err
			}
			inv, _, err := collect.Take(context.Background(), collect.Options{
				Root: root, Images: tf.images, RootFS: tf.rootfs, PullImages: recording == "", CLIVersion: version.Version,
			})
			if err != nil {
				return err
			}
			rep := match.Check(context.Background(), inv, src, match.Options{EPSSThreshold: threshold})
			res := buildGateResult(inv, rep, fail, allowIncomplete)
			if jsonFlag(c) {
				if err := writeJSON(env.Stdout, res); err != nil {
					return err
				}
			} else {
				printGate(env.Stdout, style{on: env.Color}, inv, res, fail)
			}
			if res.ExitCode != ExitOK {
				return &exitError{code: res.ExitCode}
			}
			return nil
		},
	}
	addTakeFlags(c, &tf)
	c.Flags().StringSliceVar(&failOn, "fail-on", []string{"malicious", "kev"}, "fail on findings that are any of: malicious, kev, severe, high")
	c.Flags().BoolVar(&allowIncomplete, "allow-incomplete", false, "exit 0 instead of 2 when the check is incomplete and nothing meets the threshold")
	c.Flags().Float64Var(&threshold, "epss-threshold", rank.DefaultEPSSThreshold, "EPSS probability at or above which a critical finding is severe")
	c.Flags().StringVar(&mirrorDir, "mirror", "", "match against a local OSV mirror (depwatch mirror sync) instead of the OSV API; a mirror whose last sync failed or is over 24 hours old makes the check incomplete")
	c.Flags().StringVar(&recording, "recording", "", "answer from a recorded set of source responses instead of the network (tests)")
	_ = c.Flags().MarkHidden("recording")
	return c
}

func gateSources(env *Env, recording string) (sources.Set, error) {
	if recording != "" {
		r, err := sources.LoadRecording(recording)
		if err != nil {
			return sources.Set{}, &usageError{msg: "reading the recording: " + err.Error()}
		}
		return r.Sources(), nil
	}
	if env.Sources != nil {
		return env.Sources()
	}
	return sources.Live(version.UserAgent(), 60*time.Second), nil
}

func parseFailOn(list []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, item := range list {
		for _, v := range strings.Split(item, ",") {
			v = strings.ToLower(strings.TrimSpace(v))
			if v == "" {
				continue
			}
			if _, ok := thresholds[v]; !ok {
				return nil, &usageError{msg: fmt.Sprintf("--fail-on %q is not one of malicious, kev, severe, high", v)}
			}
			out[v] = true
		}
	}
	if len(out) == 0 {
		return nil, &usageError{msg: "--fail-on needs at least one of malicious, kev, severe, high"}
	}
	return out, nil
}

// meets reports whether a finding meets any chosen threshold.
func meets(f match.Finding, fail map[string]bool) bool {
	if fail["malicious"] && f.Malicious {
		return true
	}
	if fail["kev"] && f.KEV != nil && f.Scope == inventory.ScopeProduction {
		return true
	}
	if fail["severe"] && f.Level == rank.Severe {
		return true
	}
	if fail["high"] && rank.Order(f.Level) >= rank.Order(rank.High) {
		return true
	}
	return false
}

// inventoryGaps turns what the inventory could not read into not-checked entries.
func inventoryGaps(inv *inventory.Inventory) []match.NotChecked {
	var out []match.NotChecked
	if inv.NothingFound() {
		out = append(out, match.NotChecked{What: "this folder", Why: nothingFoundWhy, Incomplete: true})
	}
	for _, f := range inv.FilesNotRead {
		out = append(out, match.NotChecked{What: f.Path, Why: f.Reason, Incomplete: true})
	}
	for _, u := range inv.Unsupported {
		out = append(out, match.NotChecked{What: u.Path, Why: u.Ecosystem + " is not supported", Incomplete: true})
	}
	for _, img := range inv.Images {
		if !img.Read {
			out = append(out, match.NotChecked{What: "image " + img.Reference, Why: img.Reason, Incomplete: true})
		} else if img.Reason != "" {
			out = append(out, match.NotChecked{What: "image " + img.Reference, Why: img.Reason})
		}
	}
	for _, c := range inv.Conflicts {
		var parts []string
		for _, r := range c.Runtimes {
			parts = append(parts, r.Version+" in "+r.SourceFile)
		}
		out = append(out, match.NotChecked{What: c.Name + " version", Why: "sources disagree: " + strings.Join(parts, ", ")})
	}
	return out
}

func buildGateResult(inv *inventory.Inventory, rep *match.Report, fail map[string]bool, allowIncomplete bool) GateResult {
	res := GateResult{
		SchemaVersion: "1", CLIVersion: version.Version, Part: inv.Part,
		Findings: rep.Findings, SourceErrors: rep.SourceErrors, MeetThreshold: []string{},
	}
	for k := range fail {
		res.FailOn = append(res.FailOn, k)
	}
	sort.Strings(res.FailOn)
	res.NotChecked = append(inventoryGaps(inv), rep.NotChecked...)
	if res.NotChecked == nil {
		res.NotChecked = []match.NotChecked{}
	}
	res.Complete = true
	for _, n := range res.NotChecked {
		if n.Incomplete {
			res.Complete = false
		}
	}
	for _, p := range inv.Packages {
		if p.Version != "" {
			res.PackagesChecked++
		}
	}
	res.PackagesChecked += len(inv.OSPackages)
	for _, f := range rep.Findings {
		if meets(f, fail) {
			res.MeetThreshold = append(res.MeetThreshold, f.ID)
		}
	}
	switch {
	case len(res.MeetThreshold) > 0:
		res.ExitCode = ExitFindings
	case !res.Complete && !allowIncomplete:
		res.ExitCode = ExitIncomplete
	default:
		res.ExitCode = ExitOK
	}
	return res
}

var labelWords = map[string]string{
	rank.LabelExploitedNow: "exploited now",
	rank.LabelMalicious:    "malicious",
	rank.LabelProvisional:  "provisional",
	rank.LabelUnscored:     "no severity stated",
	rank.LabelDevelopment:  "development only",
}

func printGate(w io.Writer, st style, inv *inventory.Inventory, res GateResult, fail map[string]bool) {
	fmt.Fprintf(w, "%s  %s\n\n", st.bold("depwatch gate"), partLine(inv))
	if len(res.Findings) == 0 {
		if inv.NothingFound() {
			fmt.Fprintln(w, st.deepOrange("No dependency files found in this folder.")+" Nothing was checked; this is not a clean result.")
		} else if res.Complete {
			fmt.Fprintln(w, st.green("No findings.")+fmt.Sprintf(" %d packages checked against OSV, CISA KEV and EPSS.", res.PackagesChecked))
		} else {
			fmt.Fprintln(w, st.deepOrange("No findings in what was checked, but the check is incomplete.")+" This is not a clean result; see below.")
		}
		fmt.Fprintln(w)
	}
	for _, f := range res.Findings {
		printFinding(w, st, f, meets(f, fail))
	}
	if len(res.NotChecked) > 0 {
		fmt.Fprintln(w, st.bold("Not checked"))
		for _, n := range res.NotChecked {
			what := n.What
			if n.Incomplete {
				what = st.deepOrange(what)
			} else {
				what = st.gray(what)
			}
			fmt.Fprintf(w, "  %s\n    %s\n", what, n.Why)
		}
		fmt.Fprintln(w)
	}
	counts := map[string]int{}
	for _, f := range res.Findings {
		counts[f.Level]++
	}
	var parts []string
	for _, l := range []string{rank.Severe, rank.High, rank.Medium, rank.Low} {
		if counts[l] > 0 {
			parts = append(parts, st.level(l, fmt.Sprintf("%d %s", counts[l], l)))
		}
	}
	summary := "no findings"
	if len(parts) > 0 {
		summary = strings.Join(parts, ", ")
	}
	fmt.Fprintf(w, "%s. Failing on: %s.\n", summary, strings.Join(res.FailOn, ", "))
	switch res.ExitCode {
	case ExitFindings:
		fmt.Fprintln(w, st.red(fmt.Sprintf("Failed: %d finding(s) meet the threshold: %s.", len(res.MeetThreshold), strings.Join(res.MeetThreshold, ", "))))
	case ExitIncomplete:
		fmt.Fprintln(w, st.deepOrange("Incomplete: the check could not look at everything. Exit 2 (--allow-incomplete to pass anyway)."))
	default:
		if res.Complete {
			fmt.Fprintln(w, st.green("Passed."))
		} else {
			fmt.Fprintln(w, st.deepOrange("Passed with --allow-incomplete; the check did not look at everything."))
		}
	}
}

func printFinding(w io.Writer, st style, f match.Finding, failing bool) {
	head := st.level(f.Level, strings.ToUpper(f.Level))
	others := []string{}
	for _, id := range f.IDs {
		if id != f.ID {
			others = append(others, id)
		}
	}
	line := fmt.Sprintf("%s  %s", head, st.bold(f.ID))
	if len(others) > 0 {
		line += "  " + st.gray(strings.Join(others, " "))
	}
	if failing {
		line += "  " + st.red("[fails the gate]")
	}
	fmt.Fprintln(w, line)
	fmt.Fprintf(w, "  %s\n", f.Summary)
	var labels []string
	for _, l := range f.Labels {
		word := labelWords[l]
		if l == rank.LabelExploitedNow || l == rank.LabelMalicious {
			word = st.red(word)
		} else if l == rank.LabelProvisional {
			word = st.deepOrange(word)
		}
		labels = append(labels, word)
	}
	meta := []string{f.Scope}
	if f.KEV != nil {
		meta = append(meta, "in CISA KEV since "+f.KEV.DateAdded)
	}
	if f.EPSS != nil {
		meta = append(meta, fmt.Sprintf("EPSS %.1f%%", f.EPSS.Probability*100))
	}
	if f.CVSS != nil {
		meta = append(meta, fmt.Sprintf("CVSS %.1f", *f.CVSS))
	} else if f.SourceLabel != "" {
		meta = append(meta, "source severity "+strings.ToLower(f.SourceLabel))
	}
	if len(labels) > 0 {
		fmt.Fprintf(w, "  %s\n", strings.Join(labels, ", "))
	}
	fmt.Fprintf(w, "  %s\n", st.gray(strings.Join(meta, ", ")))
	fmt.Fprintf(w, "  %s\n", st.gray("why: "+f.Reason))
	for _, p := range f.Places {
		where := p.SourceFile
		if p.Image != "" {
			where = p.Image + " " + p.SourceFile
		}
		fmt.Fprintf(w, "  %s %s  %s  %s\n", p.Name, p.Version, st.gray(where), st.gray(p.Scope))
		switch {
		case len(p.Paths) > 0:
			for _, path := range p.Paths {
				names := make([]string, len(path))
				for i, s := range path {
					names[i] = s.Name
				}
				fmt.Fprintf(w, "    %s\n", strings.Join(names, " > "))
			}
			if p.MorePaths > 0 {
				fmt.Fprintf(w, "    %s\n", st.gray(fmt.Sprintf("and %d more paths", p.MorePaths)))
			}
		case p.Kind == "os_package":
			fmt.Fprintf(w, "    %s\n", st.gray("operating system package"))
		default:
			fmt.Fprintf(w, "    %s\n", st.gray("path not recorded"))
		}
		switch {
		case p.FixedSameMajor != "":
			fmt.Fprintf(w, "    fix: %s\n", st.green(p.FixedSameMajor))
		case p.FixedLowest != "":
			fmt.Fprintf(w, "    fix: %s %s\n", st.green(p.FixedLowest), st.deepOrange("(a new major version)"))
		default:
			fmt.Fprintf(w, "    %s\n", st.deepOrange("no fixed version published"))
		}
	}
	fmt.Fprintln(w)
}
