package cli

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/kimathinjoki/watchdep-cli/internal/testutil"
)

// listing writes a folder's files as "<path> <size>" lines, as a forge's tree would give them.
func listing(t *testing.T, root string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		info, _ := d.Info()
		rel, _ := filepath.Rel(root, p)
		lines = append(lines, filepath.ToSlash(rel)+" "+itoa(info.Size()))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func wanted(t *testing.T, root string) []string {
	t.Helper()
	var out bytes.Buffer
	code := Run([]string{"wanted", "--json"}, Env{Stdout: &out, Stderr: &out, Stdin: strings.NewReader(listing(t, root))})
	if code != 0 {
		t.Fatalf("wanted: exit %d %s", code, out.String())
	}
	var res struct {
		Paths []string `json:"paths"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	return res.Paths
}

// comparable drops what differs by route: when and how the inventory was taken, and the part.
func comparable(t *testing.T, raw string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	for _, k := range []string{"taken_at", "taken_by", "part"} {
		delete(m, k)
	}
	b, _ := json.Marshal(m)
	return string(b)
}

// Parity: for every corpus and fixture folder, copying only the wanted files gives the same inventory
// as reading the whole folder, so the GitHub route reads exactly what the CLI route reads.
func TestWantedParity(t *testing.T) {
	var roots []string
	cases, _ := os.ReadDir("../../testdata/corpus")
	for _, c := range cases {
		roots = append(roots, filepath.Join("../../testdata/corpus", c.Name(), "project"))
	}
	roots = append(roots, "../../testdata/fixtures/monorepo", "../../testdata/fixtures/rootfs-debian")
	for _, root := range roots {
		t.Run(root, func(t *testing.T) {
			full := testutil.CopyDir(t, root)
			// Source files a repository also holds: never wanted.
			for _, src := range []string{"app/models/user.rb", "src/index.js", "main.go", "lib/app.py"} {
				p := filepath.Join(full, src)
				_ = os.MkdirAll(filepath.Dir(p), 0o755)
				_ = os.WriteFile(p, []byte("source"), 0o644)
			}
			paths := wanted(t, full)
			for _, p := range paths {
				for _, src := range []string{"user.rb", "index.js", "main.go", "app.py"} {
					if strings.HasSuffix(p, src) {
						t.Fatalf("a source file was wanted: %s", p)
					}
				}
			}
			fetched := t.TempDir()
			for _, p := range paths {
				b, err := os.ReadFile(filepath.Join(full, p))
				if err != nil {
					t.Fatal(err)
				}
				dst := filepath.Join(fetched, p)
				_ = os.MkdirAll(filepath.Dir(dst), 0o755)
				if err := os.WriteFile(dst, b, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			_, a, _ := run(t, nil, "inventory", "--json", full)
			_, b, _ := run(t, nil, "inventory", "--json", "--taken-by", "github", "--commit", "abc", "--branch", "main", fetched)
			if comparable(t, a) != comparable(t, b) {
				t.Fatalf("the routes differ.\nCLI:    %s\nGitHub: %s", comparable(t, a), comparable(t, b))
			}
			var doc struct {
				TakenBy string `json:"taken_by"`
				Part    struct{ Commit, Branch string }
			}
			_ = json.Unmarshal([]byte(b), &doc)
			if doc.TakenBy != "github" || doc.Part.Commit != "abc" || doc.Part.Branch != "main" {
				t.Fatalf("%+v", doc)
			}
		})
	}
}

func TestWantedSkipsInstalledAndIgnoredFolders(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "watchdep.yml")
	_ = os.WriteFile(cfg, []byte("ignore:\n  - legacy\n"), 0o644)
	var out bytes.Buffer
	in := "package-lock.json 10\nnode_modules/a/package-lock.json 10\nvendor/b/composer.lock 5\nlegacy/Gemfile.lock 9\nweb/yarn.lock 4\nREADME.md 3\n.nvmrc 2\nDockerfile 9\n"
	if code := Run([]string{"wanted", "--config", cfg}, Env{Stdout: &out, Stderr: &out, Stdin: strings.NewReader(in)}); code != 0 {
		t.Fatalf("exit %d %s", code, out.String())
	}
	got := strings.Fields(out.String())
	want := []string{".nvmrc", "Dockerfile", "package-lock.json", "web/yarn.lock"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%v, want %v", got, want)
	}
}
