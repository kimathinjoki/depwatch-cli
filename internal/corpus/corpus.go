// Package corpus runs the known incidents corpus: real historical cases, with real versions and
// recorded source responses, end to end through watchdep gate.
package corpus

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kimathinjoki/watchdep-cli/internal/cli"
	"github.com/kimathinjoki/watchdep-cli/internal/sources"
)

// Dir is the corpus folder, relative to this package.
const Dir = "../../testdata/corpus"

// Cases is every case the corpus must hold. Removing a folder fails the build.
var Cases = []string{
	"critical-no-epss", "dev-only-critical", "event-stream", "incomplete", "log4shell",
	"osv-stalled", "python-uv", "rails-rack", "ua-parser-js", "xz-backdoor",
}

// Case is a case's case.json.
type Case struct {
	Description string   `json:"description"`
	Args        []string `json:"args"`
	DropEPSS    bool     `json:"drop_epss,omitempty"`
	Fail        []string `json:"fail,omitempty"`
	Key         string   `json:"key,omitempty"`
	KeyLevel    string   `json:"key_level,omitempty"`
	KeyLabels   []string `json:"key_labels,omitempty"`
	KeyPaths    []string `json:"key_paths,omitempty"`
}

// ExpectedFinding is one finding a case must produce.
type ExpectedFinding struct {
	ID     string   `json:"id"`
	Level  string   `json:"level"`
	Labels []string `json:"labels"`
}

// Expected is a case's expected.json.
type Expected struct {
	ExitCode     int               `json:"exit_code"`
	Complete     bool              `json:"complete"`
	SourceErrors []string          `json:"source_errors"`
	Findings     []ExpectedFinding `json:"findings"`
}

// Load reads a case.
func Load(name string) (Case, error) {
	var c Case
	raw, err := os.ReadFile(filepath.Join(Dir, name, "case.json"))
	if err != nil {
		return c, err
	}
	err = json.Unmarshal(raw, &c)
	return c, err
}

// LoadExpected reads a case's expected result.
func LoadExpected(name string) (Expected, error) {
	var e Expected
	raw, err := os.ReadFile(filepath.Join(Dir, name, "expected.json"))
	if err != nil {
		return e, err
	}
	err = json.Unmarshal(raw, &e)
	return e, err
}

// Run runs gate on the case with the given sources and returns its JSON result and exit code.
func Run(name string, c Case, src sources.Set) (cli.GateResult, int, error) {
	project := filepath.Join(Dir, name, "project")
	args := []string{"gate", "--json"}
	for i := 0; i < len(c.Args); i++ {
		a := c.Args[i]
		args = append(args, a)
		if (a == "--rootfs" || a == "--image") && i+1 < len(c.Args) {
			args = append(args, filepath.Join(project, c.Args[i+1]))
			i++
		}
	}
	args = append(args, project)
	var out, errb bytes.Buffer
	code := cli.Run(args, cli.Env{Stdout: &out, Stderr: &errb, Sources: func() (sources.Set, error) { return src, nil }})
	var res cli.GateResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		return res, code, fmt.Errorf("gate output is not JSON: %v\n%s\n%s", err, out.String(), errb.String())
	}
	return res, code, nil
}

// Summarize turns a gate result into the expected shape.
func Summarize(res cli.GateResult, code int) Expected {
	e := Expected{ExitCode: code, Complete: res.Complete, SourceErrors: res.SourceErrors, Findings: []ExpectedFinding{}}
	if e.SourceErrors == nil {
		e.SourceErrors = []string{}
	}
	for _, f := range res.Findings {
		labels := f.Labels
		if labels == nil {
			labels = []string{}
		}
		e.Findings = append(e.Findings, ExpectedFinding{ID: f.ID, Level: f.Level, Labels: labels})
	}
	sort.Slice(e.Findings, func(i, j int) bool { return e.Findings[i].ID < e.Findings[j].ID })
	return e
}

// Diff describes how got differs from want; empty when they agree.
func Diff(want, got Expected) string {
	var d []string
	if want.ExitCode != got.ExitCode {
		d = append(d, fmt.Sprintf("exit code %d, want %d", got.ExitCode, want.ExitCode))
	}
	if want.Complete != got.Complete {
		d = append(d, fmt.Sprintf("complete %v, want %v", got.Complete, want.Complete))
	}
	if strings.Join(want.SourceErrors, ",") != strings.Join(got.SourceErrors, ",") {
		d = append(d, fmt.Sprintf("source errors %v, want %v", got.SourceErrors, want.SourceErrors))
	}
	wm := map[string]ExpectedFinding{}
	for _, f := range want.Findings {
		wm[f.ID] = f
	}
	gm := map[string]ExpectedFinding{}
	for _, f := range got.Findings {
		gm[f.ID] = f
		w, ok := wm[f.ID]
		switch {
		case !ok:
			d = append(d, fmt.Sprintf("new finding %s %s %v", f.ID, f.Level, f.Labels))
		case w.Level != f.Level || strings.Join(w.Labels, ",") != strings.Join(f.Labels, ","):
			d = append(d, fmt.Sprintf("%s is %s %v, want %s %v", f.ID, f.Level, f.Labels, w.Level, w.Labels))
		}
	}
	for _, f := range want.Findings {
		if _, ok := gm[f.ID]; !ok {
			d = append(d, fmt.Sprintf("missing finding %s %s %v", f.ID, f.Level, f.Labels))
		}
	}
	return strings.Join(d, "\n")
}

// Sources builds a case's recorded sources.
func Sources(name string, c Case) (sources.Set, error) {
	r, err := sources.LoadRecording(filepath.Join(Dir, name, "recording.json"))
	if err != nil {
		return sources.Set{}, err
	}
	r.Fail = c.Fail
	return r.Sources(), nil
}
