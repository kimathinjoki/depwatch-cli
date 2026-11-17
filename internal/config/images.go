package config

import (
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kimathinjoki/watchdep-cli/internal/inventory"
)

// imageRuntimes maps an official image's name to the runtime or database it runs. Many projects
// state their runtime only here (FROM node:18, image: postgres:12), so an image names its version as
// a version file does.
var imageRuntimes = map[string]string{
	"node": "node", "python": "python", "ruby": "ruby", "golang": "go", "php": "php", "rust": "rust",
	"elixir": "elixir", "erlang": "erlang", "denoland/deno": "deno", "oven/bun": "bun",
	"openjdk": "java", "eclipse-temurin": "java", "amazoncorretto": "java", "ibm-semeru-runtimes": "java",
	"sapmachine": "java", "azul/zulu-openjdk": "java", "bellsoft/liberica-openjdk-debian": "java",
	"dotnet/runtime": "dotnet", "dotnet/aspnet": "dotnet", "dotnet/sdk": "dotnet",
	"postgres": "postgres", "postgis/postgis": "postgres", "mysql": "mysql", "mariadb": "mariadb",
	"redis": "redis", "mongo": "mongodb",
	"bitnami/node": "node", "bitnami/python": "python", "bitnami/ruby": "ruby", "bitnami/postgresql": "postgres",
	"bitnami/mysql": "mysql", "bitnami/mariadb": "mariadb", "bitnami/redis": "redis", "bitnami/mongodb": "mongodb",
}

// Distroless images carry the runtime and its major version in the name (gcr.io/distroless/nodejs20-debian12).
var distrolessRe = regexp.MustCompile(`^distroless/(nodejs|python|java)(\d+)(?:-|$)`)

// tagVersionRe is the version at the start of a tag: 16 in 16-bullseye, 3.12.1 in 3.12.1-slim, 21.0.1
// in 21.0.1_12-jre, 8 in 8u342-jre. A tag with none (latest, alpine, lts) names no version.
var tagVersionRe = regexp.MustCompile(`^v?(\d+(?:\.\d+){0,2})`)

// RuntimeFromImage is the runtime or database an image reference runs, with the version its tag
// names, listed as coming from file. ok is false for an image watchdep does not know, or a tag that
// names no version.
func RuntimeFromImage(ref, file string) (inventory.Runtime, bool) {
	name, tag := splitImage(ref)
	if name == "" {
		return inventory.Runtime{}, false
	}
	var rt, version string
	if m := distrolessRe.FindStringSubmatch(name); m != nil {
		rt, version = map[string]string{"nodejs": "node", "python": "python", "java": "java"}[m[1]], m[2]
	} else {
		rt = imageRuntimes[name]
		if m := tagVersionRe.FindStringSubmatch(tag); m != nil {
			version = m[1]
		}
	}
	if rt == "" || version == "" {
		return inventory.Runtime{}, false
	}
	kind := inventory.KindRuntime
	if databaseNames[rt] {
		kind = inventory.KindDatabase
	}
	return inventory.Runtime{Kind: kind, Name: rt, Version: version, SourceFile: file}, true
}

// splitImage takes an image reference apart into its repository name, without the registry and
// docker.io's library/, and its tag. A digest is dropped; no tag is an empty tag.
func splitImage(ref string) (string, string) {
	ref = strings.TrimSpace(ref)
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if ref == "" || strings.Contains(ref, "$") {
		return "", ""
	}
	name, tag := ref, ""
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		name, tag = ref[:i], ref[i+1:]
	}
	name = strings.ToLower(name)
	if parts := strings.SplitN(name, "/", 2); len(parts) == 2 && (strings.ContainsAny(parts[0], ".:") || parts[0] == "localhost") {
		name = parts[1] // a registry: docker.io, ghcr.io, mcr.microsoft.com, gcr.io, public.ecr.aws
	}
	name = strings.TrimPrefix(name, "library/")
	name = strings.TrimPrefix(name, "docker/library/") // public.ecr.aws/docker/library/node
	return name, tag
}

// IsComposeFile reports whether a file is a Docker Compose file: compose.yaml, docker-compose.yml,
// and their variants such as docker-compose.prod.yml or compose.override.yaml.
func IsComposeFile(p string) bool {
	b := strings.ToLower(path.Base(p))
	if !strings.HasSuffix(b, ".yml") && !strings.HasSuffix(b, ".yaml") {
		return false
	}
	return strings.HasPrefix(b, "compose.") || strings.HasPrefix(b, "docker-compose.")
}

// ReadCompose lists the runtimes and databases of a Compose file's service images. A service built
// from a Dockerfile is read from that Dockerfile instead. ok is false for a file that is not YAML.
func ReadCompose(file string, content []byte) ([]inventory.Runtime, bool) {
	var doc struct {
		Services map[string]struct {
			Image string `yaml:"image"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return nil, false
	}
	names := make([]string, 0, len(doc.Services))
	for n := range doc.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []inventory.Runtime
	for _, n := range names {
		if r, ok := RuntimeFromImage(doc.Services[n].Image, file); ok {
			out = append(out, r)
		}
	}
	return out, true
}
