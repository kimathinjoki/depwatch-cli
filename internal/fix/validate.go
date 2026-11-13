package fix

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// The server says what to upgrade; nothing it sends is trusted further than this. A source file must
// lie inside the repository, and a name or version must look like one of its ecosystem's, so neither
// can reach a file outside the repository or turn into a package manager's flag.

var (
	// plainVersion is a version and nothing else: no range, no URL, no git or file spec.
	plainVersion = regexp.MustCompile(`^v?[0-9]+(\.[0-9A-Za-z]+)*([-+~][0-9A-Za-z.+~-]*)?$`)
	npmName      = regexp.MustCompile(`^(@[A-Za-z0-9][A-Za-z0-9._~-]*/)?[A-Za-z0-9_][A-Za-z0-9._~-]*$`)
	composerName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$`)
	gemName      = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]*$`)
	pypiName     = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	goModule     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]*(/[A-Za-z0-9._~-]+)*$`)
	crateName    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)
	imageRef     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]*$`)
)

// nameRule gives the name rule for the lockfile a fixer works on.
func nameRule(base string) *regexp.Regexp {
	switch {
	case base == "package-lock.json", base == "npm-shrinkwrap.json", base == "yarn.lock", base == "pnpm-lock.yaml", base == "bun.lock":
		return npmName
	case base == "composer.lock":
		return composerName
	case base == "Gemfile.lock", base == "gems.locked":
		return gemName
	case base == "poetry.lock", base == "uv.lock", base == "Pipfile.lock", strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		return pypiName
	case base == "go.mod":
		return goModule
	case base == "Cargo.lock":
		return crateName
	}
	return nil
}

// Check refuses a target the server sent that is not safe to act on, and cleans its source file. It
// is called before anything is read or changed.
func Check(root string, t *Target) error {
	if !plainVersion.MatchString(t.Fix) {
		return fmt.Errorf("the fix version %q is not a plain version; refused", t.Fix)
	}
	if t.Kind == "os_package" {
		if t.Image != "" && !imageRef.MatchString(t.Image) {
			return fmt.Errorf("the image %q is not an image reference; refused", t.Image)
		}
		return nil
	}
	if t.Version != "" && !plainVersion.MatchString(t.Version) {
		return fmt.Errorf("the version %q is not a plain version; refused", t.Version)
	}
	clean, err := insideRoot(root, t.SourceFile)
	if err != nil {
		return err
	}
	t.SourceFile = clean
	rule := nameRule(path.Base(clean))
	if strings.HasPrefix(t.Name, "-") || strings.Contains(t.Name, "..") || (rule != nil && !rule.MatchString(t.Name)) {
		return fmt.Errorf("%q is not a package name of %s; refused", t.Name, path.Base(clean))
	}
	return nil
}

// insideRoot cleans a slash path the server sent and checks it names a file inside root, after
// following symbolic links.
func insideRoot(root, p string) (string, error) {
	refuse := fmt.Errorf("the source file %q is not inside the repository; refused", p)
	if p == "" || strings.Contains(p, "\\") || strings.ContainsRune(p, 0) || path.IsAbs(p) || filepath.IsAbs(p) || filepath.VolumeName(p) != "" {
		return "", refuse
	}
	clean := path.Clean(p)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", refuse
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(filepath.Join(root, filepath.FromSlash(clean)))
	if err != nil {
		return "", fmt.Errorf("the source file %s could not be found: %w", clean, err)
	}
	rel, err := filepath.Rel(realRoot, real)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", refuse
	}
	if st, err := os.Stat(real); err != nil || !st.Mode().IsRegular() {
		return "", refuse
	}
	return clean, nil
}
