package cli

import (
	"archive/zip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kimathinjoki/depwatch-cli/internal/mirror"
)

func importMirror(t *testing.T, entries map[string]map[string]any) string {
	t.Helper()
	archive := filepath.Join(t.TempDir(), "all.zip")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for id, e := range entries {
		w, _ := zw.Create(id + ".json")
		_ = json.NewEncoder(w).Encode(e)
	}
	_ = zw.Close()
	_ = f.Close()
	dir := t.TempDir()
	if _, err := (&mirror.Syncer{Dir: dir}).Import("npm", archive); err != nil {
		t.Fatal(err)
	}
	return dir
}

func osvEntry(id, name, summary string) map[string]any {
	return map[string]any{"id": id, "summary": summary, "affected": []any{map[string]any{
		"package": map[string]any{"ecosystem": "npm", "name": name}, "versions": []string{"1.0.0"}}}}
}

// depwatch mirror package lists every advisory for one package; the server builds related advisories from it.
func TestMirrorPackage(t *testing.T) {
	dir := importMirror(t, map[string]map[string]any{
		"GHSA-a": osvEntry("GHSA-a", "x", "first"), "GHSA-b": osvEntry("GHSA-b", "x", "second"), "GHSA-c": osvEntry("GHSA-c", "y", "other"),
	})
	code, out, errOut := run(t, nil, "mirror", "package", "--dir", dir, "npm", "x", "--json")
	var got struct {
		Advisories []struct{ ID string } `json:"advisories"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &got) != nil || len(got.Advisories) != 2 || got.Advisories[0].ID != "GHSA-a" || got.Advisories[1].ID != "GHSA-b" {
		t.Fatalf("%d %q %q", code, out, errOut)
	}
	if code, out, _ := run(t, nil, "mirror", "package", "--dir", dir, "npm", "absent", "--json"); code != 0 || !strings.Contains(out, `"advisories": []`) {
		t.Fatalf("an unknown package is an empty list: %d %q", code, out)
	}
	if code, _, _ := run(t, nil, "mirror", "package", "--dir", dir, "PyPI", "x"); code == 0 {
		t.Fatal("an ecosystem the mirror does not hold must not answer as an empty list")
	}
	if code, out, _ := run(t, nil, "mirror", "package", "--dir", dir, "npm", "x"); code != 0 || !strings.Contains(out, "GHSA-b  second") {
		t.Fatalf("%d %q", code, out)
	}
}
