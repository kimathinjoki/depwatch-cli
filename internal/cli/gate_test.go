package cli

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/kimathinjoki/watchdep-cli/internal/sources"
	"github.com/kimathinjoki/watchdep-cli/internal/testutil"
)

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

func lockWith(name, version string, dev bool) map[string]string {
	devField := ""
	section := "dependencies"
	if dev {
		devField = `,"dev":true`
		section = "devDependencies"
	}
	return map[string]string{
		"package.json":      `{"` + section + `":{"` + name + `":"*"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"` + section + `":{"` + name + `":"*"}},"node_modules/` + name + `":{"version":"` + version + `"` + devField + `}}}`,
	}
}

func kevRecording() *sources.Recording {
	return &sources.Recording{
		OSVQueries: map[string][]string{"npm|exploited|1.0.0": {"GHSA-kev"}, "npm|risky|1.0.0": {"GHSA-crit"}},
		OSVVulns: map[string]*sources.Vuln{
			"GHSA-kev":  {ID: "GHSA-kev", Aliases: []string{"CVE-2099-0001"}, Summary: "exploited", Severity: []sources.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}},
			"GHSA-crit": {ID: "GHSA-crit", Aliases: []string{"CVE-2099-0002"}, Summary: "critical, unscored", Severity: []sources.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}},
		},
		KEV:       map[string]sources.KEVEntry{"CVE-2099-0001": {CVE: "CVE-2099-0001", DateAdded: "2099-01-01"}},
		KEVAsked:  []string{"CVE-2099-0001", "CVE-2099-0002"},
		EPSS:      map[string]sources.EPSSScore{"CVE-2099-0001": {CVE: "CVE-2099-0001", Probability: 0.5}},
		EPSSAsked: []string{"CVE-2099-0001", "CVE-2099-0002"},
	}
}

// A lockfile with a KEV-listed package in production exits 1 with the default threshold.
func TestGateKEVInProduction(t *testing.T) {
	dir := testutil.Tree(t, lockWith("exploited", "1.0.0", false))
	code, out, _ := run(t, kevRecording(), "gate", dir)
	if code != ExitFindings || !strings.Contains(out, "exploited now") || !strings.Contains(out, "CVE-2099-0001") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// The same package in development scope exits 0 with the default threshold and still lists it.
func TestGateKEVInDevelopment(t *testing.T) {
	dir := testutil.Tree(t, lockWith("exploited", "1.0.0", true))
	code, out, _ := run(t, kevRecording(), "gate", dir)
	if code != ExitOK || !strings.Contains(out, "CVE-2099-0001") || !strings.Contains(out, "development only") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// An unreachable OSV exits 2, and exits 0 with --allow-incomplete only when nothing else is found.
func TestGateUnreachableOSV(t *testing.T) {
	dir := testutil.Tree(t, lockWith("exploited", "1.0.0", false))
	r := kevRecording()
	r.Fail = []string{sources.NameOSV}
	code, out, _ := run(t, r, "gate", dir)
	if code != ExitIncomplete || !strings.Contains(out, "OSV") || strings.Contains(out, "No findings.") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if code, _, _ := run(t, r, "gate", "--allow-incomplete", dir); code != ExitOK {
		t.Fatalf("--allow-incomplete: exit %d", code)
	}
	// With a finding meeting the threshold, the finding wins over incomplete.
	both := testutil.Tree(t, lockWith("exploited", "1.0.0", false))
	writeFile(t, both+"/build.sbt", "x")
	if code, _, _ := run(t, kevRecording(), "gate", "--allow-incomplete", both); code != ExitFindings {
		t.Fatalf("a finding meeting the threshold wins: exit %d", code)
	}
	if code, _, _ := run(t, kevRecording(), "gate", both); code != ExitFindings {
		t.Fatalf("a finding meeting the threshold wins over incomplete: exit %d", code)
	}
}

// --fail-on severe exits 1 on a provisional severe.
func TestGateFailOnSevereProvisional(t *testing.T) {
	dir := testutil.Tree(t, lockWith("risky", "1.0.0", false))
	if code, _, _ := run(t, kevRecording(), "gate", dir); code != ExitOK {
		t.Fatalf("default threshold: exit %d", code)
	}
	code, out, _ := run(t, kevRecording(), "gate", "--fail-on", "severe", dir)
	if code != ExitFindings || !strings.Contains(out, "provisional") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

// The JSON output carries the same findings, levels and labels as the human output.
func TestGateJSONMatchesHuman(t *testing.T) {
	dir := testutil.Tree(t, lockWith("exploited", "1.0.0", false))
	_, human, _ := run(t, kevRecording(), "gate", dir)
	code, js, _ := run(t, kevRecording(), "gate", "--json", dir)
	var res GateResult
	if err := json.Unmarshal([]byte(js), &res); err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != code || len(res.Findings) != 1 {
		t.Fatalf("%+v", res)
	}
	f := res.Findings[0]
	if !strings.Contains(human, strings.ToUpper(f.Level)+"  "+f.ID) {
		t.Fatalf("human output lacks %s %s:\n%s", f.Level, f.ID, human)
	}
	for _, l := range f.Labels {
		if !strings.Contains(human, labelWords[l]) {
			t.Fatalf("human output lacks label %s", l)
		}
	}
}

// Runtimes appear in the gate's output as listed but not checked: the gate has no runtime source.
func TestGateListsRuntimesAsNotChecked(t *testing.T) {
	dir := testutil.Tree(t, map[string]string{".ruby-version": "3.3.4\n", "go.mod": "module x\n\ngo 1.22\n"})
	_, out, _ := run(t, &sources.Recording{OSVQueries: map[string][]string{}}, "gate", dir)
	if !strings.Contains(out, "ruby 3.3.4") || !strings.Contains(out, "not checked by the gate") {
		t.Fatalf("%s", out)
	}
}

// A folder with no dependency files at all (a workflow that forgot to check the code out) is not a
// clean result: the gate exits 2 and says plainly that nothing was found to check.
func TestGateNothingToCheckIsIncomplete(t *testing.T) {
	dir := testutil.Tree(t, map[string]string{"README.md": "hello", ".ruby-version": "3.3.4\n"})
	code, out, _ := run(t, &sources.Recording{OSVQueries: map[string][]string{}}, "gate", dir)
	if code != ExitIncomplete || !strings.Contains(out, "No dependency files found in this folder") || strings.Contains(out, "Passed") {
		t.Fatalf("exit %d\n%s", code, out)
	}
	_, js, _ := run(t, &sources.Recording{OSVQueries: map[string][]string{}}, "gate", "--json", dir)
	var res GateResult
	if err := json.Unmarshal([]byte(js), &res); err != nil {
		t.Fatal(err)
	}
	if res.Complete || res.ExitCode != ExitIncomplete || len(res.NotChecked) == 0 {
		t.Fatalf("%+v", res)
	}
	// A lockfile with no packages in it was looked at: that is a clean, complete result.
	empty := testutil.Tree(t, map[string]string{"package.json": `{}`, "package-lock.json": `{"lockfileVersion":3,"packages":{"":{}}}`})
	if code, out, _ := run(t, &sources.Recording{OSVQueries: map[string][]string{}}, "gate", empty); code != ExitOK {
		t.Fatalf("an empty lockfile was read: exit %d\n%s", code, out)
	}
}

// A path that does not exist is a usage error naming the path given.
func TestGateMissingPathIsUsage(t *testing.T) {
	missing := t.TempDir() + "/nowhere"
	for _, cmd := range []string{"gate", "inventory"} {
		code, _, errOut := run(t, nil, cmd, missing)
		if code != ExitUsage || !strings.Contains(errOut, missing) {
			t.Fatalf("%s: exit %d: %s", cmd, code, errOut)
		}
	}
	file := testutil.Tree(t, map[string]string{"a.txt": "x"}) + "/a.txt"
	if code, _, errOut := run(t, nil, "gate", file); code != ExitUsage || !strings.Contains(errOut, "not a folder") {
		t.Fatalf("a file: exit %d: %s", code, errOut)
	}
}

// inventory and gate agree on "nothing found": a lockfile that lists no packages was read, so it is not
// "no dependency files"; an empty folder is.
func TestInventoryNothingFoundAgreesWithGate(t *testing.T) {
	empty := testutil.Tree(t, map[string]string{"README.md": "hello"})
	_, out, _ := run(t, &sources.Recording{}, "inventory", empty)
	if !strings.Contains(out, "No dependency files found in this folder") {
		t.Fatalf("empty folder:\n%s", out)
	}
	lock := testutil.Tree(t, map[string]string{
		"package.json":      `{"name":"x","version":"1.0.0"}`,
		"package-lock.json": `{"name":"x","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"x","version":"1.0.0"}}}`,
	})
	_, out, _ = run(t, &sources.Recording{}, "inventory", lock)
	if strings.Contains(out, "No dependency files found") {
		t.Fatalf("a lockfile with no packages was read:\n%s", out)
	}
}
