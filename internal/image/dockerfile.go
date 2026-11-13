package image

import (
	"bufio"
	"path"
	"regexp"
	"strings"
)

// IsDockerfile reports whether a file is a Dockerfile (Dockerfile, Dockerfile.prod, app.Dockerfile, Containerfile).
func IsDockerfile(p string) bool {
	b := path.Base(p)
	return b == "Dockerfile" || b == "Containerfile" || strings.HasPrefix(b, "Dockerfile.") || strings.HasSuffix(b, ".Dockerfile")
}

var (
	fromRe = regexp.MustCompile(`(?i)^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?`)
	argRe  = regexp.MustCompile(`(?i)^ARG\s+([A-Za-z_][A-Za-z0-9_]*)(?:=(.*))?$`)
	varRe  = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`)
)

// BaseImage is the image a Dockerfile's final stage is built on.
type BaseImage struct {
	Reference string
	// Unresolved is set when the reference uses a build argument with no default.
	Unresolved string
}

// FinalBase returns the base image of the Dockerfile's final stage, following stage names
// ("FROM builder") back to a real image. Earlier stages are build time only and do not ship.
// ok is false for FROM scratch or a file with no FROM.
func FinalBase(content string) (BaseImage, bool) {
	args := map[string]string{}
	stages := map[string]string{}
	var last string
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := argRe.FindStringSubmatch(line); m != nil && last == "" {
			args[m[1]] = strings.Trim(strings.TrimSpace(m[2]), `"'`)
			continue
		}
		if m := fromRe.FindStringSubmatch(line); m != nil {
			ref := m[1]
			if m[2] != "" {
				stages[strings.ToLower(m[2])] = ref
			}
			last = ref
		}
	}
	if last == "" {
		return BaseImage{}, false
	}
	ref := last
	for i := 0; i < 20; i++ {
		next, ok := stages[strings.ToLower(ref)]
		if !ok {
			break
		}
		ref = next
	}
	var missing string
	ref = varRe.ReplaceAllStringFunc(ref, func(v string) string {
		name := varRe.FindStringSubmatch(v)[1]
		if val, ok := args[name]; ok && val != "" {
			return val
		}
		missing = name
		return v
	})
	if strings.EqualFold(ref, "scratch") {
		return BaseImage{}, false
	}
	if missing != "" {
		return BaseImage{Reference: ref, Unresolved: missing}, true
	}
	return BaseImage{Reference: ref}, true
}
