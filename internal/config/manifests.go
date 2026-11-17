package config

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/kimathinjoki/watchdep-cli/internal/inventory"
)

// manifestFiles are files that state a runtime version among other things: a package manifest's
// engines or required language version, a toolchain file, a build file's Java release.
var manifestFiles = map[string]bool{
	"package.json": true, "pyproject.toml": true, "Pipfile": true, "runtime.txt": true, "go.mod": true,
	"composer.json": true, "Gemfile": true, "global.json": true, "rust-toolchain": true,
	"rust-toolchain.toml": true, ".java-version": true, ".sdkmanrc": true, "mise.toml": true,
	".mise.toml": true, "pom.xml": true, "build.gradle": true, "build.gradle.kts": true,
}

var (
	exactRe    = regexp.MustCompile(`^\d+(?:\.\d+){0,2}$`)
	wildRe     = regexp.MustCompile(`^(\d+(?:\.\d+)?)\.[xX*]$`)
	caretRe    = regexp.MustCompile(`^\^\s*(\d+)(?:\.(\d+))?(?:\.\d+)?$`)
	tildeRe    = regexp.MustCompile(`^~\s*(\d+)(?:\.(\d+))?(?:\.\d+)?$`)
	pessimisRe = regexp.MustCompile(`^(?:~>|~=)\s*(\d+(?:\.\d+){1,2})$`)
)

// Release is the release a version requirement is confined to, or false when it is open-ended. An
// exact version stays as written; 16.x and 3.11.* are 16 and 3.11; ^18.2.0 is 18 (^0.4 is 0.4);
// ~16.2.0 is 16.2; Ruby's ~> 3.3.0 and Python's ~= 3.11.2 drop the last part (3.3, 3.11). >=16, a
// list of ranges, or an alias names no release: production could run any version it allows.
func Release(spec string) (string, bool) {
	s := strings.TrimSpace(spec)
	s = strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(s, "=="), "="), "v")
	s = strings.TrimSpace(s)
	switch {
	case exactRe.MatchString(s):
		return s, true
	case wildRe.MatchString(s):
		return wildRe.FindStringSubmatch(s)[1], true
	case caretRe.MatchString(s):
		m := caretRe.FindStringSubmatch(s)
		if m[1] == "0" && m[2] != "" {
			return "0." + m[2], true
		}
		return m[1], true
	case tildeRe.MatchString(s):
		m := tildeRe.FindStringSubmatch(s)
		if m[2] == "" {
			return m[1], true
		}
		return m[1] + "." + m[2], true
	case pessimisRe.MatchString(s):
		v := pessimisRe.FindStringSubmatch(s)[1]
		return v[:strings.LastIndex(v, ".")], true
	}
	return "", false
}

// javaRelease turns a Java version as build files and version managers write it into its release:
// 1.8 is 8, 17.0.2 stays, temurin-17.0.2 and 17.0.2-tem are 17.0.2.
var javaNumRe = regexp.MustCompile(`(\d+(?:\.\d+){0,2})`)

func javaRelease(s string) (string, bool) {
	m := javaNumRe.FindString(s)
	if m == "" {
		return "", false
	}
	if strings.HasPrefix(m, "1.") {
		m = strings.SplitN(strings.TrimPrefix(m, "1."), ".", 2)[0]
	}
	return m, true
}

var (
	gemfileRubyRe  = regexp.MustCompile(`(?m)^\s*ruby\s*\(?\s*["']([^"']+)["']`)
	goDirectiveRe  = regexp.MustCompile(`(?m)^go\s+(\d+(?:\.\d+){1,2})\s*$`)
	goToolchainRe  = regexp.MustCompile(`(?m)^toolchain\s+go(\d+(?:\.\d+){1,2})\s*$`)
	pomRe          = regexp.MustCompile(`<(maven\.compiler\.release|java\.version|maven\.compiler\.target|maven\.compiler\.source)>\s*([^<$\s]+)\s*</`)
	gradleToolRe   = regexp.MustCompile(`(?:JavaLanguageVersion\.of|jvmToolchain)\(\s*(\d+)\s*\)`)
	gradleCompatRe = regexp.MustCompile(`(?:sourceCompatibility|targetCompatibility)\s*=\s*(?:JavaVersion\.VERSION_(\d+(?:_\d+)?)|['"]?(\d+(?:\.\d+)?)['"]?)`)
	runtimeTxtRe   = regexp.MustCompile(`^python-(\d+(?:\.\d+){0,2})$`)
	rustChannelRe  = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)
)

// ReadManifest reads the runtime versions a manifest, toolchain or build file states.
func ReadManifest(file string, content []byte) []inventory.Runtime {
	var out []inventory.Runtime
	add := func(name, version string) {
		if version != "" {
			out = append(out, inventory.Runtime{Kind: inventory.KindRuntime, Name: name, Version: version, SourceFile: file})
		}
	}
	addRange := func(name, spec string) {
		if v, ok := Release(spec); ok {
			add(name, v)
		}
	}
	text := string(content)
	switch path.Base(file) {
	case "package.json":
		var doc struct {
			Engines map[string]any `json:"engines"`
		}
		if json.Unmarshal(content, &doc) == nil {
			if s, ok := doc.Engines["node"].(string); ok {
				addRange("node", s)
			}
		}
	case "composer.json":
		var doc struct {
			Require map[string]any `json:"require"`
			Config  struct {
				Platform map[string]any `json:"platform"`
			} `json:"config"`
		}
		if json.Unmarshal(content, &doc) == nil {
			// config.platform.php is the version Composer resolves for; require.php is what the
			// project allows.
			if s, ok := doc.Config.Platform["php"].(string); ok {
				addRange("php", s)
			} else if s, ok := doc.Require["php"].(string); ok {
				addRange("php", s)
			}
		}
	case "global.json":
		var doc struct {
			SDK struct {
				Version string `json:"version"`
			} `json:"sdk"`
		}
		if json.Unmarshal(content, &doc) == nil {
			// An SDK version (8.0.100) runs the runtime of its major and minor (8.0).
			if p := strings.Split(doc.SDK.Version, "."); len(p) >= 2 && exactRe.MatchString(p[0]+"."+p[1]) {
				add("dotnet", p[0]+"."+p[1])
			}
		}
	case "pyproject.toml":
		var doc struct {
			Project struct {
				RequiresPython string `toml:"requires-python"`
			} `toml:"project"`
			Tool struct {
				Poetry struct {
					Dependencies map[string]any `toml:"dependencies"`
				} `toml:"poetry"`
			} `toml:"tool"`
		}
		if _, err := toml.Decode(text, &doc); err == nil {
			if doc.Project.RequiresPython != "" {
				addRange("python", doc.Project.RequiresPython)
			} else if s, ok := doc.Tool.Poetry.Dependencies["python"].(string); ok {
				addRange("python", s)
			}
		}
	case "Pipfile":
		var doc struct {
			Requires struct {
				Full    string `toml:"python_full_version"`
				Version string `toml:"python_version"`
			} `toml:"requires"`
		}
		if _, err := toml.Decode(text, &doc); err == nil {
			if doc.Requires.Full != "" {
				addRange("python", doc.Requires.Full)
			} else {
				addRange("python", doc.Requires.Version)
			}
		}
	case "runtime.txt":
		if m := runtimeTxtRe.FindStringSubmatch(strings.TrimSpace(text)); m != nil {
			add("python", m[1])
		}
	case "go.mod":
		// The toolchain builds the binary, and its standard library ships in it; the go line is the
		// oldest release the module accepts, and the toolchain when none is named.
		if m := goToolchainRe.FindStringSubmatch(text); m != nil {
			add("go", m[1])
		} else if m := goDirectiveRe.FindStringSubmatch(text); m != nil {
			add("go", m[1])
		}
	case "Gemfile":
		if m := gemfileRubyRe.FindStringSubmatch(text); m != nil {
			addRange("ruby", m[1])
		}
	case "rust-toolchain", "rust-toolchain.toml":
		channel := strings.TrimSpace(text)
		var doc struct {
			Toolchain struct {
				Channel string `toml:"channel"`
			} `toml:"toolchain"`
		}
		if _, err := toml.Decode(text, &doc); err == nil && doc.Toolchain.Channel != "" {
			channel = doc.Toolchain.Channel
		}
		if rustChannelRe.MatchString(channel) { // stable, nightly and dated channels name no release
			add("rust", channel)
		}
	case ".java-version":
		for _, l := range strings.Split(text, "\n") {
			if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
				if v, ok := javaRelease(l); ok {
					add("java", v)
				}
				break
			}
		}
	case ".sdkmanrc":
		for _, l := range strings.Split(text, "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
			if ok && strings.TrimSpace(k) == "java" {
				if r, ok := javaRelease(v); ok {
					add("java", r)
				}
			}
		}
	case "mise.toml", ".mise.toml":
		var doc struct {
			Tools map[string]any `toml:"tools"`
		}
		if _, err := toml.Decode(text, &doc); err == nil {
			for _, tool := range sortedKeys(doc.Tools) {
				v := doc.Tools[tool]
				if list, ok := v.([]any); ok && len(list) > 0 {
					v = list[0]
				}
				s, ok := v.(string)
				name, known := toolNames[tool]
				if !ok || !known {
					continue
				}
				if r, ok := Release(s); ok {
					kind := inventory.KindRuntime
					if databaseNames[name] {
						kind = inventory.KindDatabase
					}
					out = append(out, inventory.Runtime{Kind: kind, Name: name, Version: r, SourceFile: file})
				}
			}
		}
	case "pom.xml":
		// The release the code is compiled for: maven.compiler.release, else Spring Boot's
		// java.version, else the target, else the source.
		found := map[string]string{}
		for _, m := range pomRe.FindAllStringSubmatch(text, -1) {
			if _, seen := found[m[1]]; !seen {
				found[m[1]] = m[2]
			}
		}
		for _, k := range []string{"maven.compiler.release", "java.version", "maven.compiler.target", "maven.compiler.source"} {
			if v, ok := found[k]; ok {
				if r, ok := javaRelease(v); ok {
					add("java", r)
				}
				break
			}
		}
	case "build.gradle", "build.gradle.kts":
		if m := gradleToolRe.FindStringSubmatch(text); m != nil {
			add("java", m[1])
		} else if m := gradleCompatRe.FindStringSubmatch(text); m != nil {
			v := strings.ReplaceAll(m[1], "_", ".")
			if v == "" {
				v = m[2]
			}
			if r, ok := javaRelease(v); ok {
				add("java", r)
			}
		}
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
