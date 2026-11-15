package fix

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/semantic"

	"github.com/kimathinjoki/watchdep-cli/internal/collect"
)

// Snapshot keeps the regular files of a folder (not its subfolders), so a fixer that did not reach the
// fix version can be undone exactly.
type Snapshot map[string][]byte

func TakeSnapshot(dir string) (Snapshot, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	s := Snapshot{}
	for _, e := range entries {
		if e.Type().IsRegular() {
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				return nil, err
			}
			s[filepath.Join(dir, e.Name())] = b
		}
	}
	return s, nil
}

// Restore puts every snapshotted file back and removes regular files that appeared since.
func (s Snapshot) Restore(dir string) error {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		if _, ok := s[p]; !ok && e.Type().IsRegular() {
			_ = os.Remove(p)
		}
	}
	for p, b := range s {
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// Verify takes the inventory again and checks the package is at or above the fix version everywhere in
// the target's file. A package no longer found in the file is not a verified fix: the change is undone
// and the fix named.
func Verify(ctx context.Context, root string, t Target) error {
	if err := Check(root, &t); err != nil {
		return err
	}
	inv, _, err := collect.Take(ctx, collect.Options{Root: root})
	if err != nil {
		return err
	}
	eco := strings.Split(t.Ecosystem, ":")[0]
	same := func(a, b string) bool { return strings.EqualFold(a, b) }
	if eco == "PyPI" || (eco == "" && strings.HasPrefix(path.Base(t.SourceFile), "requirements")) {
		same = func(a, b string) bool { return normPy(a) == normPy(b) }
	}
	found := false
	for _, p := range inv.Packages {
		if p.SourceFile != t.SourceFile || !same(p.Name, t.Name) {
			continue
		}
		found = true
		v, err := semantic.Parse(p.Version, eco)
		if err != nil {
			return fmt.Errorf("the new version %s of %s could not be compared: %w", p.Version, t.Name, err)
		}
		if c, err := v.CompareStr(t.Fix); err != nil || c < 0 {
			return fmt.Errorf("%s is at %s after the change, below the fix %s (a constraint holds it back)", t.Name, p.Version, t.Fix)
		}
	}
	if !found {
		for _, f := range inv.FilesNotRead {
			if f.Path == t.SourceFile {
				return fmt.Errorf("%s could not be read after the change: %s", path.Base(t.SourceFile), f.Reason)
			}
		}
		return fmt.Errorf("%s was not found in %s after the change, so the fix could not be shown", t.Name, t.SourceFile)
	}
	return nil
}
