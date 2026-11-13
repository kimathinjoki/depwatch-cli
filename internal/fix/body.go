package fix

import (
	"fmt"
	"regexp"
	"strings"
)

// Item is one finding the server asks a pull request for.
type Item struct {
	FindingID int64    `json:"finding_id"`
	PrimaryID string   `json:"primary_id"`
	IDs       []string `json:"ids"`
	Level     string   `json:"level"`
	Summary   string   `json:"summary"`
	Reason    string   `json:"reason"`
	Labels    []string `json:"labels"`
	URL       string   `json:"url"`
	Targets   []Target `json:"targets"`
	CodeCheck *struct {
		Verdict  string `json:"verdict"`
		Reason   string `json:"reason"`
		Evidence []struct {
			Path string `json:"path"`
			Line int    `json:"line"`
			Note string `json:"note"`
		} `json:"evidence"`
	} `json:"code_check"`
	PullRequest *struct {
		Number int    `json:"number"`
		URL    string `json:"url"`
		Branch string `json:"branch"`
		State  string `json:"state"`
	} `json:"pull_request"`
}

var unsafeBranch = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// BranchName is one branch per finding per part.
func BranchName(item Item, part string) string {
	return "depwatch/" + strings.Trim(unsafeBranch.ReplaceAllString(strings.ToLower(item.PrimaryID+"-"+part), "-"), "-")
}

// Title of the pull request.
func Title(item Item, t Target) string {
	return fmt.Sprintf("Upgrade %s to %s (%s, %s)", t.Name, t.Fix, item.PrimaryID, item.Level)
}

var labelWords = map[string]string{"exploited_now": "exploited now (CISA KEV)", "malicious": "a malicious release", "provisional": "provisional: no exploit score yet", "development_only": "development only"}

// Body describes the advisory, the level, why it matters, the path, the code check and the strategy,
// and says a person merges.
func Body(item Item, part string, changes map[string]Change) string {
	var b strings.Builder
	fmt.Fprintf(&b, "depwatch found **%s** (%s) in %s: %s\n\n", item.PrimaryID, item.Level, part, item.Summary)
	var why []string
	for _, l := range item.Labels {
		if w, ok := labelWords[l]; ok {
			why = append(why, w)
		}
	}
	fmt.Fprintf(&b, "**Why it matters:** %s.", strings.TrimSpace(item.Reason))
	if len(why) > 0 {
		fmt.Fprintf(&b, " It is %s.", strings.Join(why, ", "))
	}
	b.WriteString("\n\n**What this changes**\n\n")
	for _, t := range item.Targets {
		c, ok := changes[t.SourceFile+"|"+t.Name]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "- `%s` %s to %s in `%s`: %s", t.Name, t.Version, t.Fix, firstNonEmpty(t.SourceFile, t.Image), c.Words)
		if c.Strategy == "override" {
			b.WriteString(". The package comes in through another dependency, so the package manager's override pins it; remove the override once that dependency ships the fix")
		}
		if t.Major {
			b.WriteString(". **This is a new major version**: check its changelog")
		}
		b.WriteString(".\n")
		for i, p := range t.Paths {
			if i == 3 {
				break
			}
			fmt.Fprintf(&b, "  - path: %s > %s\n", part, strings.Join(p, " > "))
		}
	}
	if item.CodeCheck != nil {
		fmt.Fprintf(&b, "\n**Code check** (a draft): %s. %s\n", strings.ReplaceAll(item.CodeCheck.Verdict, "_", " "), item.CodeCheck.Reason)
		for i, e := range item.CodeCheck.Evidence {
			if i == 10 {
				break
			}
			fmt.Fprintf(&b, "- `%s:%d` %s\n", e.Path, e.Line, e.Note)
		}
	}
	fmt.Fprintf(&b, "\nAdvisories: %s. The finding: %s\n\n", strings.Join(item.IDs, ", "), item.URL)
	b.WriteString("Your CI tests this change. **A person approves and merges it: depwatch never merges.**\n")
	return b.String()
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
