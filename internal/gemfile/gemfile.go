// Package gemfile reads gem declarations and their Bundler groups from a Gemfile.
//
// Gemfile.lock does not record groups, so the Gemfile is the only place that says which gems are
// development only. The reader handles the plain forms (gem lines, group blocks, group: options).
package gemfile

import (
	"bufio"
	"regexp"
	"strings"
)

// Gem is one gem a Gemfile declares.
type Gem struct {
	Name        string
	Requirement string
	Groups      []string
	DevOnly     bool
}

var (
	gemLineRe   = regexp.MustCompile(`^\s*gem\s+["']([^"']+)["']\s*((?:,\s*["'][^"']*["']\s*)*)(.*)$`)
	gemReqRe    = regexp.MustCompile(`["']([^"']*)["']`)
	groupOpenRe = regexp.MustCompile(`^\s*group\s+(.+?)\s+do\s*(\|.*\|)?\s*$`)
	symbolRe    = regexp.MustCompile(`:(\w+)|["'](\w+)["']`)
	inlineGrpRe = regexp.MustCompile(`(?:group|groups):\s*(\[[^\]]*\]|:\w+|["']\w+["'])`)
	blockOpenRe = regexp.MustCompile(`\bdo\s*(\|.*\|)?\s*$`)
)

// devGroups are Bundler groups that do not ship to production.
var devGroups = map[string]bool{"development": true, "test": true, "ci": true, "lint": true, "rubocop": true, "tools": true}

// ParseGemfile reads gem declarations and their groups from a Gemfile, line by line. It reads only
// the plain forms (gem lines, group blocks, group: options); a gem it cannot place in a group is
// production, which is the louder answer.
func Parse(src string) []Gem {
	var out []Gem
	type block struct{ groups []string }
	var stack []block
	sc := bufio.NewScanner(strings.NewReader(src))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 && !strings.ContainsAny(line[:i], `"'`) {
			line = line[:i]
		}
		trim := strings.TrimSpace(line)
		if trim == "" {
			continue
		}
		if m := groupOpenRe.FindStringSubmatch(trim); m != nil {
			stack = append(stack, block{groups: symbols(m[1])})
			continue
		}
		if trim == "end" {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if m := gemLineRe.FindStringSubmatch(trim); m != nil {
			var reqs []string
			for _, r := range gemReqRe.FindAllStringSubmatch(m[2], -1) {
				reqs = append(reqs, r[1])
			}
			var groups []string
			for _, b := range stack {
				groups = append(groups, b.groups...)
			}
			if gm := inlineGrpRe.FindStringSubmatch(m[3]); gm != nil {
				groups = append(groups, symbols(gm[1])...)
			}
			out = append(out, Gem{Name: m[1], Requirement: strings.Join(reqs, ", "), Groups: groups, DevOnly: allDev(groups)})
			continue
		}
		if blockOpenRe.MatchString(trim) {
			// another block (platforms, source, path, git): it does not change groups
			stack = append(stack, block{})
		}
	}
	return out
}

func symbols(s string) []string {
	var out []string
	for _, m := range symbolRe.FindAllStringSubmatch(s, -1) {
		if m[1] != "" {
			out = append(out, m[1])
		} else {
			out = append(out, m[2])
		}
	}
	return out
}

func allDev(groups []string) bool {
	if len(groups) == 0 {
		return false
	}
	for _, g := range groups {
		if !devGroups[g] {
			return false
		}
	}
	return true
}
