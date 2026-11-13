package fix

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/kimathinjoki/depwatch-cli/internal/discover"
	"github.com/kimathinjoki/depwatch-cli/internal/image"
)

// DigestResolver gives the current digest of an image tag. Tests replace it.
type DigestResolver func(ref string) (string, error)

// RegistryDigest asks the registry, with the machine's registry credentials.
func RegistryDigest(ref string) (string, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return "", err
	}
	desc, err := remote.Head(r)
	if err != nil {
		return "", err
	}
	return desc.Digest.String(), nil
}

var fromDigest = regexp.MustCompile(`(?im)^(\s*FROM\s+(?:--platform=\S+\s+)?)([^\s@]+)@(sha256:[0-9a-f]{64})`)

// RefreshBaseImage moves every Dockerfile line that pins the image by digest to the tag's current digest,
// which carries the distribution's fixed packages. An image not pinned by digest needs no change:
// rebuilding pulls the fixed packages.
func RefreshBaseImage(root, imageRef string, resolve DigestResolver) (Change, error) {
	repoTag := imageRef
	if i := strings.Index(repoTag, "@"); i >= 0 {
		repoTag = repoTag[:i]
	}
	changed := []string{}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && discover.SkippedDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if !image.IsDockerfile(p) {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return nil
		}
		text := string(raw)
		var rerr error
		out := fromDigest.ReplaceAllStringFunc(text, func(line string) string {
			m := fromDigest.FindStringSubmatch(line)
			if m[2] != repoTag && !strings.HasPrefix(imageRef, m[2]+"@") {
				return line
			}
			digest, err := resolve(m[2])
			if err != nil {
				rerr = err
				return line
			}
			return m[1] + m[2] + "@" + digest
		})
		if rerr != nil {
			return rerr
		}
		if out != text {
			rel, _ := filepath.Rel(root, p)
			changed = append(changed, filepath.ToSlash(rel))
			return os.WriteFile(p, []byte(out), 0o644)
		}
		return nil
	})
	if err != nil {
		return Change{}, err
	}
	if len(changed) == 0 {
		return Change{}, fmt.Errorf("%s is not pinned by digest in any Dockerfile: rebuilding the image pulls the fixed packages", repoTag)
	}
	return Change{"digest", fmt.Sprintf("%s moves to the current digest of %s", strings.Join(changed, ", "), repoTag)}, nil
}
