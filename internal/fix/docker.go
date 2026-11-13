package fix

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/osv-scalibr/semantic"

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
	var images []string
	originals := map[string][]byte{}
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
			images = append(images, m[2]+"@"+digest)
			return m[1] + m[2] + "@" + digest
		})
		if rerr != nil {
			return rerr
		}
		if out != text {
			rel, _ := filepath.Rel(root, p)
			changed = append(changed, filepath.ToSlash(rel))
			originals[p] = raw
			return os.WriteFile(p, []byte(out), 0o644)
		}
		return nil
	})
	if err != nil {
		restore(originals)
		return Change{}, err
	}
	if len(changed) == 0 {
		return Change{}, fmt.Errorf("%s is not pinned by digest in any Dockerfile: rebuilding the image pulls the fixed packages", repoTag)
	}
	return Change{Strategy: "digest", Words: fmt.Sprintf("%s moves to the current digest of %s", strings.Join(changed, ", "), repoTag),
		images: uniq(images), originals: originals}, nil
}

// ImageReader reads an image's operating system packages. Tests replace it.
type ImageReader func(ctx context.Context, ref string) image.Result

// verifyImages reads each new image and checks the package is at or above the fix version in it, as
// a fresh inventory would. A new image that still carries the package below the fix undoes the change.
// One that cannot be read leaves the change, marked plainly as not verified.
func verifyImages(ctx context.Context, ch Change, t Target, read ImageReader) (Change, error) {
	if read == nil {
		ch.Unverified = "the new image was not read here"
		return ch, nil
	}
	eco := strings.Split(t.Ecosystem, ":")[0]
	var unverified, seen []string
	for _, ref := range ch.images {
		r := read(ctx, ref)
		if !r.Image.Read {
			unverified = append(unverified, fmt.Sprintf("%s could not be read (%s)", ref, firstNonEmpty(r.Image.Reason, "no reason given")))
			continue
		}
		found := false
		for _, p := range r.Packages {
			v := ""
			switch {
			case p.SourceName == t.Name:
				v = firstNonEmpty(p.SourceVersion, p.Version)
			case p.Name == t.Name:
				v = p.Version
			default:
				continue
			}
			found = true
			below, err := versionBelow(v, t.Fix, firstNonEmpty(eco, p.Distribution))
			if err != nil {
				unverified = append(unverified, fmt.Sprintf("%s %s in %s could not be compared with %s", t.Name, v, ref, t.Fix))
				continue
			}
			if below {
				restore(ch.originals)
				return Change{}, fmt.Errorf("the current digest of %s still carries %s %s, below the fix %s; the distribution has not shipped it to this image yet", ref, t.Name, v, t.Fix)
			}
			seen = appendNew(seen, v)
		}
		if !found {
			unverified = append(unverified, fmt.Sprintf("%s was not found in %s", t.Name, ref))
		}
	}
	if len(unverified) > 0 {
		ch.Unverified = strings.Join(unverified, "; ")
	} else if len(seen) > 0 {
		ch.Words += fmt.Sprintf("; the new image carries %s %s", t.Name, strings.Join(seen, ", "))
	}
	return ch, nil
}

func versionBelow(v, fix, eco string) (bool, error) {
	pv, err := semantic.Parse(v, eco)
	if err != nil {
		return false, err
	}
	c, err := pv.CompareStr(fix)
	if err != nil {
		return false, err
	}
	return c < 0, nil
}

// Undo puts back the files a digest change wrote. Other changes are undone from a Snapshot.
func (c Change) Undo() { restore(c.originals) }

func restore(originals map[string][]byte) {
	for p, b := range originals {
		_ = os.WriteFile(p, b, 0o644)
	}
}

func uniq(s []string) []string {
	var out []string
	for _, v := range s {
		out = appendNew(out, v)
	}
	return out
}

func appendNew(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
