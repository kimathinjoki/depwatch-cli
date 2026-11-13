// Package match checks an inventory against the sources and turns the answers into ranked findings.
//
// One finding is one issue: advisories that name each other as aliases are joined, and the finding
// lists every place (package, file, path) it affects. Anything that could not be checked is listed,
// with the reason, and makes the check incomplete.
package match

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	cvss2 "github.com/pandatix/go-cvss/20"
	cvss30 "github.com/pandatix/go-cvss/30"
	cvss31 "github.com/pandatix/go-cvss/31"
	cvss40 "github.com/pandatix/go-cvss/40"

	"github.com/google/osv-scalibr/semantic"

	"github.com/kimathinjoki/depwatch-cli/internal/inventory"
	"github.com/kimathinjoki/depwatch-cli/internal/rank"
	"github.com/kimathinjoki/depwatch-cli/internal/sources"
)

// Lanes.
const (
	LaneConfirmed    = "confirmed"
	LaneEarlyWarning = "early_warning"
)

// Place is one package a finding affects.
type Place struct {
	Kind      string `json:"kind"` // "package" or "os_package"
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	// SourceName is the distribution's source package, which OSV keys OS advisories by.
	SourceName    string             `json:"source_name,omitempty"`
	SourceFile    string             `json:"source_file"`
	Image         string             `json:"image,omitempty"`
	Scope         string             `json:"scope"`
	ScopeRecorded bool               `json:"scope_recorded"`
	Relation      string             `json:"relation"`
	Paths         [][]inventory.Step `json:"paths"`
	MorePaths     int                `json:"more_paths"`
	PathsRecorded bool               `json:"paths_recorded"`
	// FixedSameMajor is the lowest fixed version on the same major line, when there is one.
	FixedSameMajor string `json:"fixed_same_major,omitempty"`
	// FixedLowest is the lowest fixed version above the one in use.
	FixedLowest string `json:"fixed_lowest,omitempty"`
}

// Finding is one advisory affecting the part.
type Finding struct {
	ID          string              `json:"id"`
	IDs         []string            `json:"ids"`
	Summary     string              `json:"summary"`
	Lane        string              `json:"lane"`
	Level       string              `json:"level"`
	Labels      []string            `json:"labels"`
	Reason      string              `json:"reason"`
	Scope       string              `json:"scope"`
	Malicious   bool                `json:"malicious"`
	KEV         *sources.KEVEntry   `json:"kev,omitempty"`
	EPSS        *sources.EPSSScore  `json:"epss,omitempty"`
	CVSS        *float64            `json:"cvss,omitempty"`
	CVSSVector  string              `json:"cvss_vector,omitempty"`
	SourceLabel string              `json:"source_label,omitempty"`
	Places      []Place             `json:"places"`
	Links       []string            `json:"links"`
	vulns       []*sources.Vuln     // the joined advisories
	byQuery     map[string]struct{} // queries that matched
}

// NotChecked is something the check did not look at, and why.
type NotChecked struct {
	What string `json:"what"`
	Why  string `json:"why"`
	// Incomplete is true when it makes the check incomplete (never read as clean).
	Incomplete bool `json:"incomplete"`
	// Ecosystem names the ecosystem left unchecked, when the gap is one ecosystem's packages.
	Ecosystem string `json:"ecosystem,omitempty"`
}

// Report is the outcome of checking one inventory.
type Report struct {
	Findings   []Finding    `json:"findings"`
	NotChecked []NotChecked `json:"not_checked"`
	// SourceErrors names each source that did not answer.
	SourceErrors []string `json:"source_errors"`
	Complete     bool     `json:"complete"`
}

// Options tune the check.
type Options struct {
	EPSSThreshold float64
	Workers       int
}

// osvEcosystems are the ecosystems OSV holds advisories for (prefix before any ":release").
var osvEcosystems = map[string]bool{
	"npm": true, "PyPI": true, "Go": true, "crates.io": true, "Maven": true, "NuGet": true,
	"Packagist": true, "RubyGems": true, "Pub": true, "Hex": true, "Hackage": true, "CRAN": true,
	"ConanCenter": true, "SwiftURL": true, "Bioconductor": true, "GHC": true, "Julia": true,
	"Debian": true, "Alpine": true, "Ubuntu": true, "Red Hat": true, "Rocky Linux": true,
	"AlmaLinux": true, "SUSE": true, "openSUSE": true, "Wolfi": true, "Chainguard": true,
	"Mageia": true, "Photon OS": true, "openEuler": true, "Azure Linux": true, "MinimOS": true,
}

func osvKnows(eco string) bool {
	base := eco
	if i := strings.Index(eco, ":"); i >= 0 {
		base = eco[:i]
	}
	return osvEcosystems[base]
}

type subject struct {
	q     sources.Query
	place Place
}

// Check runs the inventory past the sources.
func Check(ctx context.Context, inv *inventory.Inventory, src sources.Set, opt Options) *Report {
	rep := &Report{Findings: []Finding{}, NotChecked: []NotChecked{}, SourceErrors: []string{}}
	failed := map[string]string{}
	fail := func(err error) {
		var se *sources.Error
		name := "a source"
		if errors.As(err, &se) {
			name = se.Source
		}
		if _, ok := failed[name]; !ok {
			failed[name] = err.Error()
		}
	}

	subjects, unknownEco, ranged := subjectsOf(inv)
	for _, eco := range sortedKeys(unknownEco) {
		rep.NotChecked = append(rep.NotChecked, NotChecked{
			What:       fmt.Sprintf("%d %s packages", unknownEco[eco], eco),
			Why:        "no advisory source depwatch reads covers this ecosystem",
			Incomplete: true,
			Ecosystem:  eco,
		})
	}
	if ranged > 0 {
		rep.NotChecked = append(rep.NotChecked, NotChecked{
			What:       fmt.Sprintf("%d packages declared with version ranges only", ranged),
			Why:        "their manifests have no lockfile; ranges are not checked in this version (add a lockfile)",
			Incomplete: true,
		})
	}
	if len(inv.Runtimes) > 0 {
		var names []string
		for _, r := range inv.Runtimes {
			names = append(names, r.Name+" "+r.Version)
		}
		rep.NotChecked = append(rep.NotChecked, NotChecked{
			What: "runtimes and databases: " + strings.Join(uniq(names), ", "),
			Why:  "listed, not checked by the gate: a depwatch server checks them against NVD and endoflife.date",
		})
	}

	// 1 and 2. Which advisories affect which package, and each advisory read once.
	ids, vulns, allIDs := lookup(ctx, subjects, src.OSV, opt.Workers, fail)
	if gr, ok := src.OSV.(sources.GapReporter); ok {
		for _, g := range gr.Gaps() {
			rep.NotChecked = append(rep.NotChecked, NotChecked{What: g.What, Why: g.Why, Incomplete: true, Ecosystem: g.Ecosystem})
		}
	}

	// 3. Join aliases into findings.
	groups := group(allIDs, vulns)
	findings := map[string]*Finding{}
	groupOf := map[string]string{}
	for root, members := range groups {
		f := &Finding{byQuery: map[string]struct{}{}}
		for _, id := range members {
			groupOf[id] = root
			if v := vulns[id]; v != nil {
				if v.Withdrawn != "" {
					continue
				}
				f.vulns = append(f.vulns, v)
			}
		}
		if len(f.vulns) == 0 {
			continue
		}
		findings[root] = f
	}
	for _, s := range subjects {
		for _, id := range ids[s.q.Key()] {
			f := findings[groupOf[id]]
			if f == nil {
				continue
			}
			if _, done := f.byQuery[s.q.Key()+"|"+s.place.SourceFile+"|"+s.place.Image]; done {
				continue
			}
			f.byQuery[s.q.Key()+"|"+s.place.SourceFile+"|"+s.place.Image] = struct{}{}
			f.Places = append(f.Places, s.place)
		}
	}

	// 4. Exploited now and the probability of exploitation, for every CVE at once.
	var cves []string
	cveSeen := map[string]bool{}
	for _, f := range findings {
		for _, c := range findingCVEs(f) {
			if !cveSeen[c] {
				cveSeen[c] = true
				cves = append(cves, c)
			}
		}
	}
	sort.Strings(cves)
	kev := map[string]sources.KEVEntry{}
	epss := map[string]sources.EPSSScore{}
	if len(cves) > 0 {
		var err error
		if kev, err = src.KEV.Lookup(ctx, cves); err != nil {
			fail(err)
			kev = map[string]sources.KEVEntry{}
		}
		if epss, err = src.EPSS.Scores(ctx, cves); err != nil {
			fail(err)
			epss = map[string]sources.EPSSScore{}
		}
	}

	// 5. Describe and rank each finding.
	for _, f := range findings {
		if len(f.Places) == 0 {
			continue
		}
		describe(f, kev, epss)
		f.Scope = inventory.ScopeDevelopment
		for _, p := range f.Places {
			if p.Scope == inventory.ScopeProduction {
				f.Scope = inventory.ScopeProduction
			}
		}
		var ep *float64
		if f.EPSS != nil {
			v := f.EPSS.Probability
			ep = &v
		}
		r := rank.Rank(rank.Input{
			Scope: f.Scope, KEV: f.KEV != nil, Malicious: f.Malicious, CVSS: f.CVSS,
			SourceLabel: f.SourceLabel, EPSS: ep, EPSSThreshold: opt.EPSSThreshold,
		})
		f.Level, f.Labels, f.Reason = r.Level, r.Labels, r.Reason
		if missingDetails(f) {
			// Ranked on what is known (a MAL- id is malicious; no severity is high), and provisional
			// until the details can be read.
			if !slices.Contains(f.Labels, rank.LabelProvisional) {
				f.Labels = append(f.Labels, rank.LabelProvisional)
			}
			f.Reason += "; provisional: OSV named this advisory but its details could not be fetched"
		}
		f.Lane = LaneConfirmed
		for i := range f.Places {
			f.Places[i].FixedSameMajor, f.Places[i].FixedLowest = fixes(f.vulns, f.Places[i])
		}
		sort.SliceStable(f.Places, func(i, j int) bool {
			a, b := f.Places[i], f.Places[j]
			if a.SourceFile != b.SourceFile {
				return a.SourceFile < b.SourceFile
			}
			return a.Name < b.Name
		})
		rep.Findings = append(rep.Findings, *f)
	}
	sort.SliceStable(rep.Findings, func(i, j int) bool {
		a, b := rep.Findings[i], rep.Findings[j]
		if rank.Order(a.Level) != rank.Order(b.Level) {
			return rank.Order(a.Level) > rank.Order(b.Level)
		}
		return a.ID < b.ID
	})

	for _, name := range sortedKeys(failed) {
		rep.SourceErrors = append(rep.SourceErrors, name)
		rep.NotChecked = append(rep.NotChecked, NotChecked{What: name, Why: failed[name], Incomplete: true})
	}
	rep.Complete = true
	for _, n := range rep.NotChecked {
		if n.Incomplete {
			rep.Complete = false
		}
	}
	return rep
}

func lookup(ctx context.Context, subjects []subject, osv sources.OSV, workers int, fail func(error)) (map[string][]string, map[string]*sources.Vuln, []string) {
	var qs []sources.Query
	for _, s := range subjects {
		qs = append(qs, s.q)
	}
	ids := map[string][]string{}
	if len(qs) > 0 {
		var err error
		ids, err = osv.Query(ctx, qs)
		if err != nil {
			fail(err)
			ids = map[string][]string{}
		}
	}
	var allIDs []string
	seen := map[string]bool{}
	for _, list := range ids {
		for _, id := range list {
			if !seen[id] {
				seen[id] = true
				allIDs = append(allIDs, id)
			}
		}
	}
	sort.Strings(allIDs)
	vulns := fetchAll(ctx, osv, allIDs, workers, fail)
	// OSV named the advisory, but its entry could not be fetched: it is kept with what is known, its
	// id, never dropped. The failure is already recorded, so the check is incomplete.
	for _, id := range allIDs {
		if vulns[id] == nil {
			vulns[id] = &sources.Vuln{ID: id, DatabaseSpecific: map[string]any{detailsMissing: true}}
		}
	}
	return ids, vulns, allIDs
}

// detailsMissing marks an advisory whose entry could not be fetched.
const detailsMissing = "depwatch_details_missing"

func missingDetails(f *Finding) bool {
	for _, v := range f.vulns {
		if v.DatabaseSpecific[detailsMissing] == true {
			return true
		}
	}
	return false
}

func subjectsOf(inv *inventory.Inventory) ([]subject, map[string]int, int) {
	var out []subject
	unknown := map[string]int{}
	ranged := 0
	for _, p := range inv.Packages {
		if p.Version == "" {
			ranged++
			continue
		}
		if !osvKnows(p.Ecosystem) {
			unknown[p.Ecosystem]++
			continue
		}
		out = append(out, subject{
			q: sources.Query{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version},
			place: Place{Kind: "package", Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version,
				SourceFile: p.SourceFile, Scope: p.Scope, ScopeRecorded: p.ScopeRecorded, Relation: p.Relation,
				Paths: p.Paths, MorePaths: p.MorePaths, PathsRecorded: p.PathsRecorded},
		})
	}
	for _, p := range inv.OSPackages {
		if !osvKnows(p.Ecosystem) || p.Ecosystem == "" {
			unknown[orUnknown(p.Distribution)]++
			continue
		}
		// OSV keys distribution advisories by source package; Debian by source version too.
		name, version := p.SourceName, p.Version
		if strings.HasPrefix(p.Ecosystem, "Debian") && p.SourceVersion != "" {
			version = p.SourceVersion
		}
		if name == "" {
			name = p.Name
		}
		where := p.SourceFile
		out = append(out, subject{
			q: sources.Query{Ecosystem: p.Ecosystem, Name: name, Version: version},
			place: Place{Kind: "os_package", Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version, SourceName: name,
				SourceFile: where, Image: p.Image, Scope: inventory.ScopeProduction, ScopeRecorded: true,
				Relation: inventory.RelationUnknown, Paths: [][]inventory.Step{}},
		})
	}
	return out, unknown, ranged
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown distribution"
	}
	return s
}

func fetchAll(ctx context.Context, osv sources.OSV, ids []string, workers int, fail func(error)) map[string]*sources.Vuln {
	if workers <= 0 {
		workers = 8
	}
	out := map[string]*sources.Vuln{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	ch := make(chan string)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range ch {
				v, err := osv.Vuln(ctx, id)
				mu.Lock()
				if err != nil {
					fail(err)
				} else {
					out[id] = v
				}
				mu.Unlock()
			}
		}()
	}
	for _, id := range ids {
		ch <- id
	}
	close(ch)
	wg.Wait()
	return out
}

// group joins advisories that name each other as aliases (or as their upstream CVE).
func group(ids []string, vulns map[string]*sources.Vuln) map[string][]string {
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		if parent[x] == "" || parent[x] == x {
			parent[x] = x
			return x
		}
		parent[x] = find(parent[x])
		return parent[x]
	}
	union := func(a, b string) {
		ra, rb := find(a), find(b)
		if ra != rb {
			if ra < rb {
				parent[rb] = ra
			} else {
				parent[ra] = rb
			}
		}
	}
	for _, id := range ids {
		find(id)
		if v := vulns[id]; v != nil {
			for _, a := range append(append([]string{}, v.Aliases...), v.Upstream...) {
				union(id, a)
			}
		}
	}
	out := map[string][]string{}
	for _, id := range ids {
		r := find(id)
		out[r] = append(out[r], id)
	}
	return out
}

func findingCVEs(f *Finding) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range f.vulns {
		for _, c := range v.CVEs() {
			if !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}
	}
	sort.Strings(out)
	return out
}

// describe fills ids, summary, malicious, severity, KEV and EPSS from the joined advisories.
func describe(f *Finding, kev map[string]sources.KEVEntry, epss map[string]sources.EPSSScore) {
	idSet := map[string]bool{}
	for _, v := range f.vulns {
		idSet[v.ID] = true
		for _, a := range v.Aliases {
			idSet[a] = true
		}
		for _, a := range v.Upstream {
			idSet[a] = true
		}
		if strings.HasPrefix(v.ID, "MAL-") || hasCWE(v, "CWE-506") {
			f.Malicious = true
		}
		for _, a := range v.Aliases {
			if strings.HasPrefix(a, "MAL-") {
				f.Malicious = true
			}
		}
		if f.Summary == "" && v.Summary != "" {
			f.Summary = v.Summary
		}
		for _, s := range allSeverities(v) {
			if score, ok := cvssScore(s); ok && (f.CVSS == nil || score > *f.CVSS) {
				sc := score
				f.CVSS = &sc
				f.CVSSVector = s.Score
			}
		}
		if l := sourceLabel(v); rank.Order(normLabel(l)) > rank.Order(normLabel(f.SourceLabel)) {
			f.SourceLabel = l
		}
		for _, r := range v.References {
			if r.Type == "ADVISORY" || r.Type == "WEB" {
				f.Links = appendUniq(f.Links, r.URL)
			}
		}
	}
	for id := range idSet {
		f.IDs = append(f.IDs, id)
	}
	sort.Strings(f.IDs)
	f.ID = primaryID(f.IDs, f.Malicious)
	if f.Summary == "" && missingDetails(f) {
		f.Summary = "OSV names " + f.ID + " for this package, but its details could not be fetched"
	}
	if f.Summary == "" {
		f.Summary = "No summary given by the source"
	}
	if len(f.Links) > 5 {
		f.Links = f.Links[:5]
	}
	f.Links = append([]string{"https://osv.dev/vulnerability/" + f.vulns[0].ID}, f.Links...)
	for _, c := range findingCVEs(f) {
		if e, ok := kev[c]; ok && f.KEV == nil {
			e := e
			f.KEV = &e
		}
		if s, ok := epss[c]; ok && (f.EPSS == nil || s.Probability > f.EPSS.Probability) {
			s := s
			f.EPSS = &s
		}
	}
}

// primaryID picks the id a finding is shown by: the CVE, else the GitHub advisory; for a malicious
// release, the malware report first.
func primaryID(ids []string, malicious bool) string {
	order := []string{"CVE-", "GHSA-", "MAL-"}
	if malicious {
		order = []string{"MAL-", "GHSA-", "CVE-"}
	}
	for _, prefix := range order {
		for _, id := range ids {
			if strings.HasPrefix(id, prefix) {
				return id
			}
		}
	}
	return ids[0]
}

func hasCWE(v *sources.Vuln, cwe string) bool {
	raw, ok := v.DatabaseSpecific["cwe_ids"].([]any)
	if !ok {
		return false
	}
	for _, c := range raw {
		if s, ok := c.(string); ok && s == cwe {
			return true
		}
	}
	return false
}

func allSeverities(v *sources.Vuln) []sources.Severity {
	out := append([]sources.Severity{}, v.Severity...)
	for _, a := range v.Affected {
		out = append(out, a.Severity...)
	}
	return out
}

func cvssScore(s sources.Severity) (float64, bool) {
	vec := strings.TrimSpace(s.Score)
	switch {
	case strings.HasPrefix(vec, "CVSS:4.0/"):
		c, err := cvss40.ParseVector(vec)
		if err != nil {
			return 0, false
		}
		return c.Score(), true
	case strings.HasPrefix(vec, "CVSS:3.1/"):
		c, err := cvss31.ParseVector(vec)
		if err != nil {
			return 0, false
		}
		return c.BaseScore(), true
	case strings.HasPrefix(vec, "CVSS:3.0/"):
		c, err := cvss30.ParseVector(vec)
		if err != nil {
			return 0, false
		}
		return c.BaseScore(), true
	case s.Type == "CVSS_V2":
		c, err := cvss2.ParseVector(vec)
		if err != nil {
			return 0, false
		}
		return c.BaseScore(), true
	}
	// Some sources put a bare number in the score.
	if f, err := strconv.ParseFloat(vec, 64); err == nil && f > 0 && f <= 10 {
		return f, true
	}
	return 0, false
}

// sourceLabel is the source's own severity word: GitHub's, or a distribution's.
func sourceLabel(v *sources.Vuln) string {
	best := ""
	consider := func(m map[string]any, key string) {
		if s, ok := m[key].(string); ok && rank.Order(normLabel(s)) > rank.Order(normLabel(best)) {
			best = s
		}
	}
	consider(v.DatabaseSpecific, "severity")
	for _, a := range v.Affected {
		consider(a.EcosystemSpecific, "severity")
		consider(a.DatabaseSpecific, "severity")
		consider(a.EcosystemSpecific, "urgency")
	}
	return best
}

func normLabel(s string) string {
	switch rank.Band(nil, s) {
	case "critical":
		return rank.Severe
	case "high":
		return rank.High
	case "medium":
		return rank.Medium
	case "low":
		return rank.Low
	}
	return ""
}

// fixes picks, from the advisories' fixed events for this package, the lowest fixed version on the
// same major line as the version in use and the lowest fixed version above it overall.
func fixes(vulns []*sources.Vuln, p Place) (string, string) {
	osvEco := p.Ecosystem
	base := osvEco
	if i := strings.Index(osvEco, ":"); i >= 0 {
		base = osvEco[:i]
	}
	current, err := semantic.Parse(p.Version, base)
	if err != nil {
		return "", ""
	}
	var candidates []string
	for _, v := range vulns {
		for _, a := range v.Affected {
			if !strings.EqualFold(a.Package.Name, p.Name) && (p.SourceName == "" || !strings.EqualFold(a.Package.Name, p.SourceName)) {
				continue
			}
			if a.Package.Ecosystem != osvEco && a.Package.Ecosystem != base {
				continue
			}
			for _, r := range a.Ranges {
				for _, e := range r.Events {
					if e.Fixed != "" {
						candidates = appendUniq(candidates, e.Fixed)
					}
				}
			}
		}
	}
	var above []string
	for _, c := range candidates {
		if cmp, err := current.CompareStr(c); err == nil && cmp < 0 {
			above = append(above, c)
		}
	}
	if len(above) == 0 {
		return "", ""
	}
	sort.SliceStable(above, func(i, j int) bool {
		vi, err := semantic.Parse(above[i], base)
		if err != nil {
			return above[i] < above[j]
		}
		c, err := vi.CompareStr(above[j])
		if err != nil {
			return above[i] < above[j]
		}
		return c < 0
	})
	lowest := above[0]
	sameMajor := ""
	for _, c := range above {
		if major(c) == major(p.Version) {
			sameMajor = c
			break
		}
	}
	return sameMajor, lowest
}

func major(v string) string {
	v = strings.TrimPrefix(v, "v")
	for i, r := range v {
		if r < '0' || r > '9' {
			return v[:i]
		}
	}
	return v
}

func appendUniq(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}

func uniq(s []string) []string {
	var out []string
	for _, x := range s {
		out = appendUniq(out, x)
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
