package match

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"

	"github.com/kimathinjoki/depwatch-cli/internal/inventory"
	"github.com/kimathinjoki/depwatch-cli/internal/sources"
)

// Matched is one package (or OS package) of an inventory with the advisories affecting it.
type Matched struct {
	Kind       string   `json:"kind"`
	Ecosystem  string   `json:"ecosystem"`
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	SourceFile string   `json:"source_file"`
	Image      string   `json:"image"`
	IDs        []string `json:"ids"`
	// Fixes holds, per advisory id, the fix versions for this package.
	Fixes map[string]Fix `json:"fixes"`
}

// Fix is the fix versions for one package and one advisory.
type Fix struct {
	SameMajor string `json:"same_major,omitempty"`
	Lowest    string `json:"lowest,omitempty"`
}

// Facts are what depwatch reads from one advisory, computed once here so the server needs no CVSS or
// version rules of its own.
type Facts struct {
	CVSS        *float64 `json:"cvss"`
	CVSSVector  string   `json:"cvss_vector,omitempty"`
	SourceLabel string   `json:"source_label,omitempty"`
	Malicious   bool     `json:"malicious"`
	CVEs        []string `json:"cves"`
	Withdrawn   bool     `json:"withdrawn"`
}

// LookupResult is what `depwatch match` answers: which advisories affect which package, the advisories
// themselves, and everything that was not checked. It does no ranking: the server ranks.
type LookupResult struct {
	SchemaVersion string                   `json:"schema_version"`
	Complete      bool                     `json:"complete"`
	Matches       []Matched                `json:"matches"`
	Advisories    map[string]*sources.Vuln `json:"advisories"`
	Facts         map[string]Facts         `json:"facts"`
	NotChecked    []NotChecked             `json:"not_checked"`
	SourceErrors  []string                 `json:"source_errors"`
	Checked       int                      `json:"checked"`
}

// Lookup answers which advisories affect each package of the inventory, from the OSV source alone.
func Lookup(ctx context.Context, inv *inventory.Inventory, osv sources.OSV, workers int) *LookupResult {
	res := &LookupResult{SchemaVersion: "1", Matches: []Matched{}, Advisories: map[string]*sources.Vuln{}, Facts: map[string]Facts{},
		NotChecked: []NotChecked{}, SourceErrors: []string{}}
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
		res.NotChecked = append(res.NotChecked, NotChecked{What: pluralPackages(unknownEco[eco], eco),
			Why: "no advisory source depwatch reads covers this ecosystem", Incomplete: true, Ecosystem: eco})
	}
	if ranged > 0 {
		res.NotChecked = append(res.NotChecked, NotChecked{What: pluralPackages(ranged, "range-only"),
			Why: "their manifests have no lockfile; ranges are not checked in this version (add a lockfile)", Incomplete: true})
	}
	ids, vulns, _ := lookup(ctx, subjects, osv, workers, fail)
	if gr, ok := osv.(sources.GapReporter); ok {
		for _, g := range gr.Gaps() {
			res.NotChecked = append(res.NotChecked, NotChecked{What: g.What, Why: g.Why, Incomplete: true, Ecosystem: g.Ecosystem})
		}
	}
	seen := map[string]bool{}
	for _, s := range subjects {
		list, answered := ids[s.q.Key()]
		if answered {
			res.Checked++
		}
		if len(list) == 0 {
			continue
		}
		key := s.place.Kind + "|" + s.q.Key() + "|" + s.place.SourceFile + "|" + s.place.Image
		if seen[key] {
			continue
		}
		seen[key] = true
		m := Matched{Kind: s.place.Kind, Ecosystem: s.place.Ecosystem, Name: s.place.Name, Version: s.place.Version,
			SourceFile: s.place.SourceFile, Image: s.place.Image, Fixes: map[string]Fix{}}
		for _, id := range list {
			if v := vulns[id]; v != nil {
				m.IDs = append(m.IDs, id)
				res.Advisories[id] = v
				res.Facts[id] = FactsOf(v)
				same, lowest := fixes([]*sources.Vuln{v}, s.place)
				if same != "" || lowest != "" {
					m.Fixes[id] = Fix{SameMajor: same, Lowest: lowest}
				}
			}
		}
		if len(m.IDs) > 0 {
			res.Matches = append(res.Matches, m)
		}
	}
	sort.SliceStable(res.Matches, func(i, j int) bool {
		a, b := res.Matches[i], res.Matches[j]
		if a.SourceFile != b.SourceFile {
			return a.SourceFile < b.SourceFile
		}
		return a.Name < b.Name
	})
	for _, name := range sortedKeys(failed) {
		res.SourceErrors = append(res.SourceErrors, name)
		res.NotChecked = append(res.NotChecked, NotChecked{What: name, Why: failed[name], Incomplete: true})
	}
	res.Complete = true
	for _, n := range res.NotChecked {
		if n.Incomplete {
			res.Complete = false
		}
	}
	return res
}

func pluralPackages(n int, what string) string {
	if what == "range-only" {
		if n == 1 {
			return "1 package declared with a version range only"
		}
		return itoa(n) + " packages declared with version ranges only"
	}
	if n == 1 {
		return "1 " + what + " package"
	}
	return itoa(n) + " " + what + " packages"
}

func itoa(n int) string { return strconv.Itoa(n) }

// FactsOf reads one advisory's severity, malicious mark and CVEs.
func FactsOf(v *sources.Vuln) Facts {
	f := Facts{CVEs: v.CVEs(), Withdrawn: v.Withdrawn != ""}
	if f.CVEs == nil {
		f.CVEs = []string{}
	}
	if strings.HasPrefix(v.ID, "MAL-") || hasCWE(v, "CWE-506") {
		f.Malicious = true
	}
	for _, a := range v.Aliases {
		if strings.HasPrefix(a, "MAL-") {
			f.Malicious = true
		}
	}
	for _, sv := range allSeverities(v) {
		if score, ok := cvssScore(sv); ok && (f.CVSS == nil || score > *f.CVSS) {
			sc := score
			f.CVSS = &sc
			f.CVSSVector = sv.Score
		}
	}
	f.SourceLabel = sourceLabel(v)
	return f
}
