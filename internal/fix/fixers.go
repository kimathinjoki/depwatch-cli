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
	// Unverified, when set, says why a fresh inventory could not show the fix (the new image could
	// not be read): the pull request says so plainly rather than claim the fix.
	Unverified string
	// images are the new image references a digest change wrote, and originals the files it changed,
	// so it can be checked and undone.
	images    []string
	originals map[string][]byte
}

// Runner runs a command in a folder. Tests replace it.
type Runner func(ctx context.Context, dir, name string, args ...string) error

// ExecRunner runs real commands, with their output kept for the error. The command gets a minimal
// environment (MinimalEnv): a package manager may run code from the packages it fetches, and that code
// must never see GITHUB_TOKEN, DEPWATCH_TOKEN or any other secret of the job.
func ExecRunner(ctx context.Context, dir, name string, args ...string) error {
	if _, err := exec.LookPath(name); err != nil {
		return fmt.Errorf("%s is not installed here: set the package manager up before depwatch fix", name)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = MinimalEnv(os.Environ())
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

// envKeep are the variables a package manager needs to find itself, its caches, its configuration
// and the network; envKeepPrefix are families of them.
var envKeep = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "SHELL": true, "TMPDIR": true, "TMP": true, "TEMP": true,
	"LANG": true, "TZ": true, "SYSTEMROOT": true, "APPDATA": true, "LOCALAPPDATA": true, "USERPROFILE": true, "PATHEXT": true, "COMSPEC": true,
	"HTTP_PROXY": true, "HTTPS_PROXY": true, "NO_PROXY": true, "http_proxy": true, "https_proxy": true, "no_proxy": true,
	"SSL_CERT_FILE": true, "SSL_CERT_DIR": true, "NODE_EXTRA_CA_CERTS": true, "REQUESTS_CA_BUNDLE": true,
	"VIRTUAL_ENV": true, "JAVA_HOME": true, "XDG_CONFIG_HOME": true, "XDG_CACHE_HOME": true, "XDG_DATA_HOME": true,
}

var envKeepPrefix = []string{"LC_", "GO", "CARGO_", "RUSTUP_", "BUNDLE_", "GEM_", "NPM_CONFIG_", "npm_config_", "YARN_", "PNPM_",
	"COREPACK_", "NVM_", "VOLTA_", "BUN_", "COMPOSER_", "PIP_", "PIPENV_", "POETRY_", "UV_", "PYENV_", "RBENV_", "ASDF_", "MISE_"}

// envSecret marks a variable as a credential, which is never passed even when its family is kept.
var envSecret = regexp.MustCompile(`(?i)TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|AUTH|_KEY$|^KEY`)

// MinimalEnv keeps from env only what package managers need, never a credential.
func MinimalEnv(env []string) []string {
	var out []string
	for _, kv := range env {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || envSecret.MatchString(k) {
			continue
		}
		keep := envKeep[k]
		for _, p := range envKeepPrefix {
			if strings.HasPrefix(k, p) {
				keep = true
			}
		}
		if keep {
			out = append(out, kv)
		}
	}
	// Yarn berry reads its own switch for lifecycle scripts; the others take a flag.
	return append(out, "YARN_ENABLE_SCRIPTS=false")
}

// ErrNoFixer is a place no fixer handles: the fix is named instead.
var ErrNoFixer = errors.New("no fixer for this package manager: the fix is named instead")

// Tools are what fixers call out to. Tests replace them.
type Tools struct {
	Run     Runner
	Resolve DigestResolver
	// ReadImage reads an image's operating system packages, to check a digest change reached the fix.
	ReadImage ImageReader
}

// Apply upgrades one place in root (the part's folder). The target is checked first (Check): a source
// file outside the repository, or a name or version that is not plausible, is refused. Direct upgrades
// pin the exact fix version, never a range that could resolve to a newer release; npm, yarn, pnpm and
// bun run with install scripts off, and Composer with scripts and plugins off.
func Apply(ctx context.Context, root string, t Target, tools Tools) (Change, error) {
	if err := Check(root, &t); err != nil {
		return Change{}, err
	}
	run := tools.Run
	if t.Kind == "os_package" {
		if t.Image == "" {
			return Change{}, fmt.Errorf("%s is an operating system package of %s: rebuild the image on a refreshed base image", t.Name, orUnknown(t.Image))
		}
		ch, err := RefreshBaseImage(root, t.Image, tools.Resolve)
		if err != nil {
			return ch, err
		}
		return verifyImages(ctx, ch, t, tools.ReadImage)
	}
	dir := filepath.Join(root, filepath.FromSlash(path.Dir(t.SourceFile)))
	base := path.Base(t.SourceFile)
	direct := t.Relation == "direct"
	exact := t.Fix
	switch {
	case base == "package-lock.json" || base == "npm-shrinkwrap.json":
		if direct {
			return Change{Strategy: "direct", Words: fmt.Sprintf("npm install %s@%s --save-exact --ignore-scripts", t.Name, exact)}, run(ctx, dir, "npm", "install", "--save-exact", "--ignore-scripts", t.Name+"@"+exact)
		}
		if err := setOverride(dir, []string{"overrides"}, t.Name, t.Fix); err != nil {
			return Change{}, err
		}
		return Change{Strategy: "override", Words: fmt.Sprintf("an npm override pins %s to %s (package.json \"overrides\"), then npm install --ignore-scripts", t.Name, t.Fix)}, run(ctx, dir, "npm", "install", "--ignore-scripts")
	case base == "yarn.lock":
		berry := exists(filepath.Join(dir, ".yarnrc.yml"))
		if direct {
			if berry {
				return Change{Strategy: "direct", Words: fmt.Sprintf("yarn up %s@%s --exact, scripts off", t.Name, exact)}, run(ctx, dir, "yarn", "up", "--exact", t.Name+"@"+exact)
			}
			return Change{Strategy: "direct", Words: fmt.Sprintf("yarn add %s@%s --exact --ignore-scripts", t.Name, exact)}, run(ctx, dir, "yarn", "add", "--exact", "--ignore-scripts", t.Name+"@"+exact)
		}
		if err := setOverride(dir, []string{"resolutions"}, t.Name, t.Fix); err != nil {
			return Change{}, err
		}
		if berry {
			return Change{Strategy: "override", Words: fmt.Sprintf("a yarn resolution pins %s to %s (package.json \"resolutions\"), then yarn install, scripts off", t.Name, t.Fix)}, run(ctx, dir, "yarn", "install", "--mode=skip-build")
		}
		return Change{Strategy: "override", Words: fmt.Sprintf("a yarn resolution pins %s to %s (package.json \"resolutions\"), then yarn install --ignore-scripts", t.Name, t.Fix)}, run(ctx, dir, "yarn", "install", "--ignore-scripts")
	case base == "pnpm-lock.yaml":
		if direct {
			return Change{Strategy: "direct", Words: fmt.Sprintf("pnpm add %s@%s --save-exact --ignore-scripts", t.Name, exact)}, run(ctx, dir, "pnpm", "add", "--save-exact", "--ignore-scripts", t.Name+"@"+exact)
		}
		if err := setOverride(dir, []string{"pnpm", "overrides"}, t.Name, t.Fix); err != nil {
			return Change{}, err
		}
		return Change{Strategy: "override", Words: fmt.Sprintf("a pnpm override pins %s to %s (package.json \"pnpm.overrides\"), then pnpm install --ignore-scripts", t.Name, t.Fix)}, run(ctx, dir, "pnpm", "install", "--ignore-scripts")
	case base == "bun.lock":
		if direct {
			return Change{Strategy: "direct", Words: fmt.Sprintf("bun add %s@%s --exact --ignore-scripts", t.Name, exact)}, run(ctx, dir, "bun", "add", "--exact", "--ignore-scripts", t.Name+"@"+exact)
		}
		if err := setOverride(dir, []string{"overrides"}, t.Name, t.Fix); err != nil {
			return Change{}, err
		}
		return Change{Strategy: "override", Words: fmt.Sprintf("a bun override pins %s to %s, then bun install --ignore-scripts", t.Name, t.Fix)}, run(ctx, dir, "bun", "install", "--ignore-scripts")
	case base == "composer.lock":
		if direct {
			return Change{Strategy: "direct", Words: fmt.Sprintf("composer require %s:%s --no-scripts --no-plugins", t.Name, exact)}, run(ctx, dir, "composer", "require", "--no-scripts", "--no-plugins", t.Name+":"+exact)
		}
		return Change{Strategy: "update", Words: fmt.Sprintf("composer update %s --with-dependencies --no-scripts --no-plugins", t.Name)}, run(ctx, dir, "composer", "update", "--with-dependencies", "--no-scripts", "--no-plugins", t.Name)
	case base == "Gemfile.lock" || base == "gems.locked":
		return Change{Strategy: "update", Words: fmt.Sprintf("bundle update --conservative %s", t.Name)}, run(ctx, dir, "bundle", "update", "--conservative", t.Name)
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return Change{Strategy: "direct", Words: fmt.Sprintf("%s pins %s==%s", base, t.Name, t.Fix)}, pinRequirement(filepath.Join(dir, base), t)
	case base == "poetry.lock":
		if direct {
			return Change{Strategy: "direct", Words: fmt.Sprintf("poetry add %s==%s", t.Name, exact)}, run(ctx, dir, "poetry", "add", t.Name+"=="+exact)
		}
		return Change{Strategy: "update", Words: fmt.Sprintf("poetry update %s", t.Name)}, run(ctx, dir, "poetry", "update", t.Name)
	case base == "uv.lock":
		return Change{Strategy: "update", Words: fmt.Sprintf("uv lock --upgrade-package %s==%s", t.Name, t.Fix)}, run(ctx, dir, "uv", "lock", "--upgrade-package", t.Name+"=="+t.Fix)
	case base == "Pipfile.lock":
		if direct {
			return Change{Strategy: "direct", Words: fmt.Sprintf("pipenv install %s==%s", t.Name, exact)}, run(ctx, dir, "pipenv", "install", t.Name+"=="+exact)
		}
		return Change{Strategy: "update", Words: fmt.Sprintf("pipenv update %s", t.Name)}, run(ctx, dir, "pipenv", "update", t.Name)
	case base == "go.mod":
		v := t.Fix
		if !strings.HasPrefix(v, "v") {
			v = "v" + v
		}
		if err := run(ctx, dir, "go", "get", t.Name+"@"+v); err != nil {
			return Change{}, err
		}
		return Change{Strategy: "update", Words: fmt.Sprintf("go get %s@%s, then go mod tidy", t.Name, v)}, run(ctx, dir, "go", "mod", "tidy")
	case base == "Cargo.lock":
		return Change{Strategy: "update", Words: fmt.Sprintf("cargo update -p %s --precise %s", t.Name, t.Fix)}, run(ctx, dir, "cargo", "update", "-p", t.Name, "--precise", t.Fix)
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
