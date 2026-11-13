// Package fix upgrades a finding's package to its fix version with the project's own package manager,
// in the project's own CI, and opens a pull request a person merges. It never merges.
package fix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Target is one place to fix, as the server sends it.
type Target struct {
	Kind       string     `json:"kind"`
	Ecosystem  string     `json:"ecosystem"`
	Name       string     `json:"name"`
	Version    string     `json:"version"`
	Fix        string     `json:"fix"`
	Major      bool       `json:"major"`
	Relation   string     `json:"relation"`
	Paths      [][]string `json:"paths"`
	SourceFile string     `json:"source_file"`
	Image      string     `json:"image"`
}

// Change is what a fixer did, in words for the pull request.
type Change struct {
	Strategy string // direct, override, update, digest
	Words    string
}

// Runner runs a command in a folder. Tests replace it.
type Runner func(ctx context.Context, dir, name string, args ...string) error

// ExecRunner runs real commands, with their output kept for the error.
func ExecRunner(ctx context.Context, dir, name string, args ...string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%s is not installed here: set the package manager up before depwatch fix", name)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		tail := strings.TrimSpace(string(out))
		if len(tail) > 600 {
			tail = tail[len(tail)-600:]
		}
		return fmt.Errorf("%s %s failed: %v: %s", name, strings.Join(args, " "), err, tail)
	}
	return nil
}

// ErrNoFixer is a place no fixer handles: the fix is named instead.
var ErrNoFixer = errors.New("no fixer for this package manager: the fix is named instead")

// Tools are what fixers call out to. Tests replace them.
type Tools struct {
	Run     Runner
	Resolve DigestResolver
}

// Apply upgrades one place in root (the part's folder).
func Apply(ctx context.Context, root string, t Target, tools Tools) (Change, error) {
	run := tools.Run
	if t.Kind == "os_package" {
		if t.Image == "" {
			return Change{}, fmt.Errorf("%s is an operating system package of %s: rebuild the image on a refreshed base image", t.Name, orUnknown(t.Image))
		}
		return RefreshBaseImage(root, t.Image, tools.Resolve)
	}
	dir := filepath.Join(root, filepath.FromSlash(path.Dir(t.SourceFile)))
	base := path.Base(t.SourceFile)
	direct := t.Relation == "direct"
	caret := "^" + t.Fix
	switch {
	case base == "package-lock.json" || base == "npm-shrinkwrap.json":
		if direct {
			return Change{"direct", fmt.Sprintf("npm install %s@%s", t.Name, caret)}, run(ctx, dir, "npm", "install", t.Name+"@"+caret)
		}
		if err := setOverride(dir, []string{"overrides"}, t.Name, t.Fix); err != nil {
			return Change{}, err
		}
		return Change{"override", fmt.Sprintf("an npm override pins %s to %s (package.json \"overrides\"), then npm install", t.Name, t.Fix)}, run(ctx, dir, "npm", "install")
	case base == "yarn.lock":
		berry := exists(filepath.Join(dir, ".yarnrc.yml"))
		if direct {
			if berry {
				return Change{"direct", fmt.Sprintf("yarn up %s@%s", t.Name, caret)}, run(ctx, dir, "yarn", "up", t.Name+"@"+caret)
			}
			return Change{"direct", fmt.Sprintf("yarn add %s@%s", t.Name, caret)}, run(ctx, dir, "yarn", "add", t.Name+"@"+caret)
		}
		if err := setOverride(dir, []string{"resolutions"}, t.Name, t.Fix); err != nil {
			return Change{}, err
		}
		return Change{"override", fmt.Sprintf("a yarn resolution pins %s to %s (package.json \"resolutions\"), then yarn install", t.Name, t.Fix)}, run(ctx, dir, "yarn", "install")
	case base == "pnpm-lock.yaml":
		if direct {
			return Change{"direct", fmt.Sprintf("pnpm add %s@%s", t.Name, caret)}, run(ctx, dir, "pnpm", "add", t.Name+"@"+caret)
		}
		if err := setOverride(dir, []string{"pnpm", "overrides"}, t.Name, t.Fix); err != nil {
			return Change{}, err
		}
		return Change{"override", fmt.Sprintf("a pnpm override pins %s to %s (package.json \"pnpm.overrides\"), then pnpm install", t.Name, t.Fix)}, run(ctx, dir, "pnpm", "install")
	case base == "bun.lock":
		if direct {
			return Change{"direct", fmt.Sprintf("bun add %s@%s", t.Name, caret)}, run(ctx, dir, "bun", "add", t.Name+"@"+caret)
		}
		if err := setOverride(dir, []string{"overrides"}, t.Name, t.Fix); err != nil {
			return Change{}, err
		}
		return Change{"override", fmt.Sprintf("a bun override pins %s to %s, then bun install", t.Name, t.Fix)}, run(ctx, dir, "bun", "install")
	case base == "composer.lock":
		if direct {
			return Change{"direct", fmt.Sprintf("composer require %s:%s", t.Name, caret)}, run(ctx, dir, "composer", "require", t.Name+":"+caret)
		}
		return Change{"update", fmt.Sprintf("composer update %s --with-dependencies", t.Name)}, run(ctx, dir, "composer", "update", t.Name, "--with-dependencies")
	case base == "Gemfile.lock" || base == "gems.locked":
		return Change{"update", fmt.Sprintf("bundle update --conservative %s", t.Name)}, run(ctx, dir, "bundle", "update", "--conservative", t.Name)
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return Change{"direct", fmt.Sprintf("%s pins %s==%s", base, t.Name, t.Fix)}, pinRequirement(filepath.Join(dir, base), t)
	case base == "poetry.lock":
		if direct {
			return Change{"direct", fmt.Sprintf("poetry add %s@%s", t.Name, caret)}, run(ctx, dir, "poetry", "add", t.Name+"@"+caret)
		}
		return Change{"update", fmt.Sprintf("poetry update %s", t.Name)}, run(ctx, dir, "poetry", "update", t.Name)
	case base == "uv.lock":
		return Change{"update", fmt.Sprintf("uv lock --upgrade-package %s==%s", t.Name, t.Fix)}, run(ctx, dir, "uv", "lock", "--upgrade-package", t.Name+"=="+t.Fix)
	case base == "Pipfile.lock":
		if direct {
			return Change{"direct", fmt.Sprintf("pipenv install %s>=%s", t.Name, t.Fix)}, run(ctx, dir, "pipenv", "install", t.Name+">="+t.Fix)
		}
		return Change{"update", fmt.Sprintf("pipenv update %s", t.Name)}, run(ctx, dir, "pipenv", "update", t.Name)
	case base == "go.mod":
		v := t.Fix
		if !strings.HasPrefix(v, "v") {
			v = "v" + v
		}
		if err := run(ctx, dir, "go", "get", t.Name+"@"+v); err != nil {
			return Change{}, err
		}
		return Change{"update", fmt.Sprintf("go get %s@%s, then go mod tidy", t.Name, v)}, run(ctx, dir, "go", "mod", "tidy")
	case base == "Cargo.lock":
		return Change{"update", fmt.Sprintf("cargo update -p %s --precise %s", t.Name, t.Fix)}, run(ctx, dir, "cargo", "update", "-p", t.Name, "--precise", t.Fix)
	}
	return Change{}, ErrNoFixer
}

// setOverride writes {keys...: {name: version}} into package.json, keeping its other content and order.
func setOverride(dir string, keys []string, name, version string) error {
	p := filepath.Join(dir, "package.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		return fmt.Errorf("the override needs package.json beside the lockfile: %w", err)
	}
	var doc orderedObject
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("package.json is not readable: %w", err)
	}
	obj := &doc
	for _, k := range keys {
		obj = obj.child(k)
	}
	obj.set(name, version)
	out, err := json.MarshalIndent(&doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, append(out, '\n'), 0o644)
}

var reqLine = regexp.MustCompile(`^(\s*)([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*==\s*([^\s;#]+)(.*)$`)

func normPy(s string) string {
	return strings.NewReplacer("_", "-", ".", "-").Replace(strings.ToLower(s))
}

// pinRequirement raises a pinned requirement line to the fix version.
func pinRequirement(file string, t Target) error {
	raw, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")
	changed := false
	for i, l := range lines {
		m := reqLine.FindStringSubmatch(l)
		if m != nil && normPy(m[2]) == normPy(t.Name) {
			lines[i] = m[1] + m[2] + m[3] + "==" + t.Fix + m[5]
			changed = true
		}
	}
	if !changed {
		return fmt.Errorf("%s is not pinned with == in %s; it comes in through another package", t.Name, filepath.Base(file))
	}
	return os.WriteFile(file, []byte(strings.Join(lines, "\n")), 0o644)
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func orUnknown(s string) string {
	if s == "" {
		return "its image"
	}
	return s
}
