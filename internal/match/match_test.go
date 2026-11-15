package match

import (
	"context"
	"slices"
	"testing"

	"github.com/kimathinjoki/watchdep-cli/internal/inventory"
	"github.com/kimathinjoki/watchdep-cli/internal/rank"
	"github.com/kimathinjoki/watchdep-cli/internal/sources"
)

func pkg(eco, name, version, scope string) inventory.Package {
	return inventory.Package{Ecosystem: eco, Name: name, Version: version, Scope: scope, ScopeRecorded: true,
		Relation: "direct", SourceFile: "package-lock.json", Paths: [][]inventory.Step{{{Name: name, Version: version}}}, PathsRecorded: true}
}

func recording() *sources.Recording {
	return &sources.Recording{
		OSVQueries: map[string][]string{
			"npm|flatmap-stream|0.1.1":                         {"GHSA-mh6f-8j2x-4483", "MAL-2025-20690"},
			"npm|event-stream|3.3.6":                           {"GHSA-mh6f-8j2x-4483"},
			"Maven|org.apache.logging.log4j:log4j-core|2.14.1": {"GHSA-jfh8-c2jp-5v3q"},
		},
		OSVVulns: map[string]*sources.Vuln{
			"GHSA-mh6f-8j2x-4483": {ID: "GHSA-mh6f-8j2x-4483", Summary: "event-stream", DatabaseSpecific: map[string]any{"severity": "CRITICAL"}},
			"MAL-2025-20690":      {ID: "MAL-2025-20690", Aliases: []string{"GHSA-mh6f-8j2x-4483"}, Summary: "Malicious code in flatmap-stream (npm)"},
			"GHSA-jfh8-c2jp-5v3q": {ID: "GHSA-jfh8-c2jp-5v3q", Aliases: []string{"CVE-2021-44228"},
				Severity: []sources.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}},
				Affected: []sources.Affected{func() sources.Affected {
					a := sources.Affected{Ranges: []sources.Range{{Type: "ECOSYSTEM", Events: []sources.Event{{Introduced: "2.13.0"}, {Fixed: "2.15.0"}}},
						{Type: "ECOSYSTEM", Events: []sources.Event{{Introduced: "2.0-beta9"}, {Fixed: "2.3.1"}}}}}
					a.Package.Ecosystem, a.Package.Name = "Maven", "org.apache.logging.log4j:log4j-core"
					return a
				}()}},
		},
		KEV:       map[string]sources.KEVEntry{"CVE-2021-44228": {CVE: "CVE-2021-44228", DateAdded: "2021-12-10"}},
		KEVAsked:  []string{"CVE-2021-44228"},
		EPSS:      map[string]sources.EPSSScore{"CVE-2021-44228": {CVE: "CVE-2021-44228", Probability: 0.97}},
		EPSSAsked: []string{"CVE-2021-44228"},
	}
}

func inv(pkgs ...inventory.Package) *inventory.Inventory {
	return &inventory.Inventory{SchemaVersion: "1", Packages: pkgs}
}

// An advisory's aliases are joined, so one issue is one finding; an OSV entry whose id starts MAL-
// is marked malicious.
func TestAliasesJoinAndMalicious(t *testing.T) {
	rep := Check(context.Background(), inv(pkg("npm", "event-stream", "3.3.6", "production"), pkg("npm", "flatmap-stream", "0.1.1", "development")), recording().Sources(), Options{})
	if len(rep.Findings) != 1 {
		t.Fatalf("want one joined finding, got %d: %+v", len(rep.Findings), rep.Findings)
	}
	f := rep.Findings[0]
	if !f.Malicious || f.ID != "MAL-2025-20690" || len(f.Places) != 2 || f.Level != rank.Severe {
		t.Fatalf("%+v", f)
	}
	if !slices.Equal(f.IDs, []string{"GHSA-mh6f-8j2x-4483", "MAL-2025-20690"}) {
		t.Fatalf("ids %v", f.IDs)
	}
	if !rep.Complete {
		t.Fatalf("not complete: %+v", rep.NotChecked)
	}
}

// A CVE listed in the KEV catalogue is marked exploited now, with the date it was added; the fix is
// the lowest fixed version above the one in use.
func TestKEVAndFix(t *testing.T) {
	rep := Check(context.Background(), inv(pkg("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "production")), recording().Sources(), Options{})
	f := rep.Findings[0]
	if f.KEV == nil || f.KEV.DateAdded != "2021-12-10" || f.ID != "CVE-2021-44228" || f.Level != rank.Severe {
		t.Fatalf("%+v", f)
	}
	if f.CVSS == nil || *f.CVSS != 10.0 {
		t.Fatalf("cvss %v", f.CVSS)
	}
	if f.Places[0].FixedLowest != "2.15.0" || f.Places[0].FixedSameMajor != "2.15.0" {
		t.Fatalf("fix %+v", f.Places[0])
	}
}

// A source that answers an error makes the check incomplete and names the source.
func TestStalledSourceIsIncomplete(t *testing.T) {
	for _, name := range []string{sources.NameOSV, sources.NameKEV, sources.NameEPSS} {
		r := recording()
		r.Fail = []string{name}
		rep := Check(context.Background(), inv(pkg("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "production")), r.Sources(), Options{})
		if rep.Complete || !slices.Contains(rep.SourceErrors, name) {
			t.Fatalf("%s failing: complete=%v errors=%v", name, rep.Complete, rep.SourceErrors)
		}
		if name == sources.NameEPSS {
			// Missing scores err toward louder: critical with no EPSS is severe, provisional.
			if f := rep.Findings[0]; f.Level != rank.Severe {
				t.Fatalf("%+v", f)
			}
		}
	}
}

func TestRangesAndUnknownEcosystemsAreNotChecked(t *testing.T) {
	p := pkg("npm", "express", "", "production")
	p.Range = "^4"
	cocoa := pkg("CocoaPods", "AFNetworking", "4.0.1", "production")
	rep := Check(context.Background(), inv(p, cocoa), recording().Sources(), Options{})
	if rep.Complete || len(rep.NotChecked) != 2 {
		t.Fatalf("%+v", rep.NotChecked)
	}
}

func TestLookupGivesFactsAndFixes(t *testing.T) {
	res := Lookup(context.Background(), inv(pkg("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1", "production")), recording().Sources().OSV, 2)
	if !res.Complete || len(res.Matches) != 1 {
		t.Fatalf("%+v", res)
	}
	m := res.Matches[0]
	if m.Fixes["GHSA-jfh8-c2jp-5v3q"].SameMajor != "2.15.0" {
		t.Fatalf("fixes %+v", m.Fixes)
	}
	f := res.Facts["GHSA-jfh8-c2jp-5v3q"]
	if f.CVSS == nil || *f.CVSS != 10.0 || f.Malicious || !slices.Equal(f.CVEs, []string{"CVE-2021-44228"}) {
		t.Fatalf("facts %+v", f)
	}
	mal := Lookup(context.Background(), inv(pkg("npm", "flatmap-stream", "0.1.1", "production")), recording().Sources().OSV, 2)
	if !mal.Facts["MAL-2025-20690"].Malicious {
		t.Fatalf("%+v", mal.Facts)
	}
}

// When OSV names an advisory but its entry cannot be fetched, the advisory is kept: a MAL- id alone
// is a severe malicious finding, any other is a provisional finding, and the check is incomplete with
// OSV's error shown.
func TestAdvisoryWhoseDetailsFailedIsKept(t *testing.T) {
	r := recording()
	r.OSVQueries["npm|evil|1.0.0"] = []string{"MAL-2099-1"}
	r.OSVQueries["npm|quiet|1.0.0"] = []string{"GHSA-gone-gone-gone"}
	rep := Check(context.Background(), inv(pkg("npm", "evil", "1.0.0", "development"), pkg("npm", "quiet", "1.0.0", "production")), r.Sources(), Options{})
	if rep.Complete || !slices.Contains(rep.SourceErrors, sources.NameOSV) {
		t.Fatalf("complete=%v errors=%v", rep.Complete, rep.SourceErrors)
	}
	byID := map[string]Finding{}
	for _, f := range rep.Findings {
		byID[f.ID] = f
	}
	mal, ok := byID["MAL-2099-1"]
	if !ok || !mal.Malicious || mal.Level != rank.Severe || len(mal.Places) != 1 {
		t.Fatalf("malicious: %+v", rep.Findings)
	}
	other, ok := byID["GHSA-gone-gone-gone"]
	if !ok || !slices.Contains(other.Labels, rank.LabelProvisional) || rank.Order(other.Level) < rank.Order(rank.High) {
		t.Fatalf("provisional: %+v", rep.Findings)
	}
}
