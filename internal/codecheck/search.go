// Package codecheck searches the code where it is for imports and calls of each finding's package, and
// drafts a verdict: used, not used, or unclear. Only paths, line numbers and (when the workspace allows
// them) short snippets ever leave the machine.
package codecheck

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/kimathinjoki/depwatch-cli/internal/discover"
)

// Verdicts.
const (
	Used    = "used"
	NotUsed = "not_used"
	Unclear = "unclear"
)

// Place is where a finding's package sits in this part, as the server sends it.
type Place struct {
	Kind      string     `json:"kind"`
	Ecosystem string     `json:"ecosystem"`
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	Relation  string     `json:"relation"`
	Paths     [][]string `json:"paths"`
}

// Finding is one open finding of the part.
type Finding struct {
	ID        int64    `json:"id"`
	PrimaryID string   `json:"primary_id"`
	Summary   string   `json:"summary"`
	Places    []Place  `json:"places"`
	Symbols   []string `json:"symbols"`
}

// Evidence is one line of code: a path relative to the part, a line number and what it shows.
type Evidence struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Note    string `json:"note"`
	Snippet string `json:"snippet,omitempty"`
}

// Result is the draft verdict for one finding.
type Result struct {
	FindingID int64      `json:"finding_id"`
	Verdict   string     `json:"verdict"`
	Reason    string     `json:"reason"`
	Evidence  []Evidence `json:"evidence"`
	Assisted  bool       `json:"assisted"`
	Model     string     `json:"model,omitempty"`
}

// MaxEvidence bounds the evidence sent per finding.
const MaxEvidence = 20

var languageFiles = map[string][]string{
	"npm":       {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"},
	"PyPI":      {".py"},
	"RubyGems":  {".rb", ".rake", ".ru"},
	"Go":        {".go"},
	"Maven":     {".java", ".kt", ".scala", ".groovy"},
	"Packagist": {".php"},
	"crates.io": {".rs"},
	"NuGet":     {".cs", ".fs", ".vb"},
	"Pub":       {".dart"},
	"Hex":       {".ex", ".exs"},
}

// buildDirs are build output and caches, never searched (installed dependencies are skipped by discover).
var buildDirs = map[string]bool{"dist": true, "build": true, "target": true, ".next": true, ".nuxt": true, "out": true, "coverage": true, "tmp": true, "log": true}

// Code is the part's source files, read once.
type Code struct {
	Root  string
	files map[string][]string // path to lines, by extension group
	byExt map[string][]string
}

// Load reads the part's source files (up to 1 MB each) for the ecosystems' languages.
func Load(root string) (*Code, error) {
	want := map[string]bool{}
	for _, exts := range languageFiles {
		for _, e := range exts {
			want[e] = true
		}
	}
	c := &Code{Root: root, files: map[string][]string{}, byExt: map[string][]string{}}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && (discover.SkippedDirs[d.Name()] || buildDirs[d.Name()]) {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if !want[ext] {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > 1<<20 {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		c.files[rel] = strings.Split(string(raw), "\n")
		c.byExt[ext] = append(c.byExt[ext], rel)
		return nil
	})
	for _, list := range c.byExt {
		sort.Strings(list)
	}
	return c, err
}

func (c *Code) filesFor(eco string) []string {
	var out []string
	for _, ext := range languageFiles[strings.Split(eco, ":")[0]] {
		out = append(out, c.byExt[ext]...)
	}
	sort.Strings(out)
	return out
}

// modules gives the names a package is imported by, per ecosystem.
func modules(eco, name string) []string {
	switch strings.Split(eco, ":")[0] {
	case "PyPI":
		n := strings.ToLower(name)
		known := map[string]string{"pyyaml": "yaml", "python-multipart": "multipart", "beautifulsoup4": "bs4", "pillow": "PIL",
			"scikit-learn": "sklearn", "python-dateutil": "dateutil", "opencv-python": "cv2", "pyjwt": "jwt", "python-jose": "jose",
			"protobuf": "google.protobuf", "msgpack-python": "msgpack", "django-rest-framework": "rest_framework", "djangorestframework": "rest_framework"}
		if m, ok := known[n]; ok {
			return []string{m}
		}
		return []string{strings.NewReplacer("-", "_", ".", "_").Replace(n)}
	case "RubyGems":
		known := map[string][]string{"actionpack": {"action_controller", "action_dispatch"}, "activesupport": {"active_support"},
			"activerecord": {"active_record"}, "actionview": {"action_view"}, "activemodel": {"active_model"}, "activejob": {"active_job"},
			"actionmailer": {"action_mailer"}, "actioncable": {"action_cable"}, "activestorage": {"active_storage"}, "railties": {"rails"}}
		if m, ok := known[name]; ok {
			return m
		}
		return []string{name, strings.ReplaceAll(name, "-", "/")}
	case "Maven":
		if i := strings.Index(name, ":"); i > 0 {
			return []string{name[:i]}
		}
	case "Packagist":
		if i := strings.Index(name, "/"); i > 0 {
			return []string{name[:i]}
		}
	case "crates.io":
		return []string{strings.ReplaceAll(name, "-", "_")}
	}
	return []string{name}
}

// importPattern matches a line importing one of the module names.
func importPattern(eco string, mods []string) *regexp.Regexp {
	alt := make([]string, len(mods))
	for i, m := range mods {
		alt[i] = regexp.QuoteMeta(m)
	}
	names := strings.Join(alt, "|")
	var expr string
	switch strings.Split(eco, ":")[0] {
	case "npm":
		expr = `(?:require\(\s*|import\s*\(\s*|from\s+|import\s+)['"](?:` + names + `)(?:/[^'"]*)?['"]`
	case "PyPI":
		expr = `^\s*(?:import\s+(?:` + names + `)(?:\.|\s|,|$)|from\s+(?:` + names + `)(?:\.\S*)?\s+import\b)`
	case "RubyGems":
		expr = `\brequire(?:_relative)?\s*\(?\s*['"](?:` + names + `)(?:/[^'"]*)?['"]|^\s*gem\s+['"](?:` + names + `)['"]`
	case "Go":
		expr = `"(?:` + names + `)(?:/[^"]*)?"`
	case "Maven":
		expr = `^\s*import\s+(?:static\s+)?(?:` + names + `)\.`
	case "Packagist":
		expr = `(?i)^\s*use\s+\\?(?:` + names + `)\\`
	case "crates.io":
		expr = `\b(?:use|extern\s+crate)\s+(?:` + names + `)\b`
	default:
		expr = `\b(?:` + names + `)\b`
	}
	return regexp.MustCompile(expr)
}

// Check drafts a verdict for one finding from the code alone.
func (c *Code) Check(f Finding) Result {
	r := Result{FindingID: f.ID, Evidence: []Evidence{}}
	var places []Place
	for _, p := range f.Places {
		if p.Kind == "package" {
			places = append(places, p)
		}
	}
	if len(places) == 0 {
		r.Verdict, r.Reason = Unclear, "The finding is in a runtime, a database or an operating system package, which the code check does not search."
		return r
	}
	var reasons []string
	verdict := ""
	for _, p := range places {
		files := c.filesFor(p.Ecosystem)
		if len(files) == 0 {
			reasons = append(reasons, fmt.Sprintf("No %s source files were found, so the use of %s could not be searched.", strings.Split(p.Ecosystem, ":")[0], p.Name))
			verdict = louder(verdict, Unclear)
			continue
		}
		mods := modules(p.Ecosystem, p.Name)
		imp := importPattern(p.Ecosystem, mods)
		var importing []string
		for _, file := range files {
			for i, line := range c.files[file] {
				if imp.MatchString(line) {
					r.add(Evidence{Path: file, Line: i + 1, Note: "imports " + p.Name})
					importing = appendUnique(importing, file)
				}
			}
		}
		calls := 0
		if len(f.Symbols) > 0 && len(importing) > 0 {
			sym := symbolPattern(f.Symbols)
			for _, file := range importing {
				for i, line := range c.files[file] {
					if m := sym.FindString(line); m != "" {
						calls++
						r.add(Evidence{Path: file, Line: i + 1, Note: "calls " + strings.TrimSpace(m)})
					}
				}
			}
		}
		switch {
		case calls > 0:
			verdict = louder(verdict, Used)
			reasons = append(reasons, fmt.Sprintf("%s is imported in %d %s, and the affected %s appear %d %s.", p.Name, len(importing), plural(len(importing), "file", "files"), plural(len(f.Symbols), "function", "functions"), calls, plural(calls, "time", "times")))
		case len(importing) > 0 && len(f.Symbols) > 0:
			verdict = louder(verdict, Unclear)
			reasons = append(reasons, fmt.Sprintf("%s is imported in %d %s, but none of the affected functions the advisory names (%s) appear; it may still reach them indirectly.", p.Name, len(importing), plural(len(importing), "file", "files"), strings.Join(f.Symbols, ", ")))
		case len(importing) > 0:
			verdict = louder(verdict, Used)
			reasons = append(reasons, fmt.Sprintf("%s is imported in %d %s; the advisory names no affected functions, so any use may reach the flaw.", p.Name, len(importing), plural(len(importing), "file", "files")))
		case p.Relation == "direct":
			verdict = louder(verdict, NotUsed)
			reasons = append(reasons, fmt.Sprintf("%s is a direct dependency, but no %s source file searched imports it (as %s).", p.Name, strings.Split(p.Ecosystem, ":")[0], strings.Join(mods, " or ")))
		default:
			verdict = louder(verdict, Unclear)
			via := "another package"
			if len(p.Paths) > 0 && len(p.Paths[0]) > 1 {
				via = strings.Join(p.Paths[0][:len(p.Paths[0])-1], " > ")
			}
			reasons = append(reasons, fmt.Sprintf("%s is not imported directly; it comes in through %s, which may use it.", p.Name, via))
		}
	}
	r.Verdict = verdict
	r.Reason = strings.Join(reasons, " ")
	return r
}

// louder keeps the verdict that hides least: used, then unclear, then not used.
func louder(a, b string) string {
	order := map[string]int{"": 0, NotUsed: 1, Unclear: 2, Used: 3}
	if order[b] > order[a] {
		return b
	}
	return a
}

func symbolPattern(symbols []string) *regexp.Regexp {
	alt := make([]string, 0, len(symbols))
	for _, s := range symbols {
		// "pkg.module.func" or "Type.Method": match the last segment as a whole word.
		last := s
		if i := strings.LastIndexAny(s, ".:#"); i >= 0 && i < len(s)-1 {
			last = s[i+1:]
		}
		alt = append(alt, regexp.QuoteMeta(last))
	}
	return regexp.MustCompile(`\b(?:` + strings.Join(alt, "|") + `)\b`)
}

func (r *Result) add(e Evidence) {
	if len(r.Evidence) < MaxEvidence {
		r.Evidence = append(r.Evidence, e)
	}
}

// Snippet returns the lines around one piece of evidence.
func (c *Code) Snippet(e Evidence, around int) string {
	lines := c.files[e.Path]
	from, to := e.Line-1-around, e.Line+around
	if from < 0 {
		from = 0
	}
	if to > len(lines) {
		to = len(lines)
	}
	var b strings.Builder
	for i := from; i < to; i++ {
		fmt.Fprintf(&b, "%d: %s\n", i+1, lines[i])
	}
	return b.String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
