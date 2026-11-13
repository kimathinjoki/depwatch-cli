package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestReferenceListsEveryVisibleCommandAndFlag(t *testing.T) {
	var out bytes.Buffer
	if code := Run([]string{"reference"}, Env{Stdout: &out, Stderr: &out}); code != ExitOK {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	var ref Reference
	if err := json.Unmarshal(out.Bytes(), &ref); err != nil {
		t.Fatal(err)
	}
	names := map[string]RefCommand{}
	var walk func(RefCommand)
	walk = func(c RefCommand) {
		names[c.Path] = c
		for _, s := range c.Commands {
			walk(s)
		}
	}
	walk(ref.Root)
	for _, want := range []string{"depwatch gate", "depwatch scan", "depwatch inventory", "depwatch mirror sync", "depwatch mirror status", "depwatch fix", "depwatch check", "depwatch deployed"} {
		if _, ok := names[want]; !ok {
			t.Errorf("%s is missing from the reference", want)
		}
	}
	for _, hidden := range []string{"depwatch reference", "depwatch help"} {
		if _, ok := names[hidden]; ok {
			t.Errorf("%s should not be in the reference", hidden)
		}
	}

	// Every flag --help shows is in the reference, and nothing else.
	root := newRoot(&Env{})
	var check func(path []string)
	check = func(path []string) {
		c, _, err := root.Find(path)
		if err != nil {
			t.Fatal(err)
		}
		rc := names[c.CommandPath()]
		got := map[string]bool{}
		for _, f := range rc.Flags {
			got[f.Name] = true
		}
		var help bytes.Buffer
		c.SetOut(&help)
		_ = c.Help()
		for _, m := range regexp.MustCompile(`(?m)^\s+(?:-\w, )?--([a-z0-9-]+)`).FindAllStringSubmatch(help.String(), -1) {
			if m[1] != "help" && !got[m[1]] {
				t.Errorf("%s: --%s is in --help but not in the reference", c.CommandPath(), m[1])
			}
		}
		for _, sub := range c.Commands() {
			if !sub.Hidden && sub.Name() != "help" {
				check(append(append([]string{}, path...), sub.Name()))
			}
		}
	}
	check([]string{})

	gate := names["depwatch gate"]
	json := false
	for _, f := range gate.Flags {
		if f.Name == "json" && f.Global {
			json = true
		}
	}
	if !json {
		t.Error("gate should carry the global --json flag")
	}
}

func TestReferenceExitCodesAreTheOnesReturned(t *testing.T) {
	want := map[int]bool{ExitOK: true, ExitFindings: true, ExitIncomplete: true, ExitUsage: true}
	if len(ExitCodes) != len(want) {
		t.Fatalf("exit codes: %v", ExitCodes)
	}
	for _, e := range ExitCodes {
		if !want[e.Code] || e.Meaning == "" {
			t.Errorf("unexpected exit code %v", e)
		}
	}
	var out bytes.Buffer
	if code := Run([]string{"gate", "--no-such-flag"}, Env{Stdout: &out, Stderr: &out}); code != ExitUsage {
		t.Errorf("a wrong flag exits %d, want %d", code, ExitUsage)
	}
}

// Every environment variable the code reads is in the reference.
func TestReferenceListsEveryEnvironmentVariable(t *testing.T) {
	listed := map[string]bool{}
	for _, e := range EnvVars {
		listed[e.Name] = true
	}
	re := regexp.MustCompile(`Getenv\("([A-Z_]+)"\)`)
	err := filepath.Walk("../..", func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return err
		}
		raw, _ := os.ReadFile(p)
		for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
			if !listed[m[1]] {
				t.Errorf("%s reads %s, which the reference does not list", p, m[1])
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
