package corpus

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/kimathinjoki/watchdep-cli/internal/cli"
)

// Every case folder is listed, and every listed case exists: dropping a case fails the build.
func TestCorpusIsWhole(t *testing.T) {
	entries, err := os.ReadDir(Dir)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, e := range entries {
		if e.IsDir() {
			found = append(found, e.Name())
		}
	}
	if !slices.Equal(found, Cases) {
		t.Fatalf("corpus folders %v, want %v", found, Cases)
	}
}

// Each case produces exactly its expected findings, levels, labels and exit code, offline.
func TestCorpus(t *testing.T) {
	for _, name := range Cases {
		t.Run(name, func(t *testing.T) {
			c, err := Load(name)
			if err != nil {
				t.Fatal(err)
			}
			want, err := LoadExpected(name)
			if err != nil {
				t.Fatal(err)
			}
			src, err := Sources(name, c)
			if err != nil {
				t.Fatal(err)
			}
			res, code, err := Run(name, c, src)
			if err != nil {
				t.Fatal(err)
			}
			if d := Diff(want, Summarize(res, code)); d != "" {
				t.Fatalf("%s\n%s", c.Description, d)
			}
			checkKey(t, c, res)
		})
	}
}

// checkKey asserts the case's named finding directly, so the expected file cannot drift from the
// case's purpose.
func checkKey(t *testing.T, c Case, res cli.GateResult) {
	t.Helper()
	if c.Key == "" {
		if res.Complete {
			t.Fatal("a case without a key finding is about incompleteness; it must not be complete")
		}
		return
	}
	for _, f := range res.Findings {
		if f.ID != c.Key && !slices.Contains(f.IDs, c.Key) {
			continue
		}
		if f.Level != c.KeyLevel {
			t.Fatalf("%s is %s, the case says %s", c.Key, f.Level, c.KeyLevel)
		}
		labels := f.Labels
		if labels == nil {
			labels = []string{}
		}
		want := c.KeyLabels
		if want == nil {
			want = []string{}
		}
		if !slices.Equal(labels, want) {
			t.Fatalf("%s labels %v, the case says %v", c.Key, labels, want)
		}
		for _, kp := range c.KeyPaths {
			ok := false
			for _, p := range f.Places {
				for _, path := range p.Paths {
					var names []string
					for _, s := range path {
						names = append(names, s.Name)
					}
					if strings.Join(names, " > ") == kp {
						ok = true
					}
				}
			}
			if !ok {
				t.Fatalf("%s has no path %q", c.Key, kp)
			}
		}
		return
	}
	t.Fatalf("the key finding %s was not found", c.Key)
}
