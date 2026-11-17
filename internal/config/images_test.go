package config

import (
	"testing"
)

// An image names its runtime and version as a version file does: official images, registries,
// digests and the common runtime images; a tag with no version, or an unknown image, names none.
func TestRuntimeFromImage(t *testing.T) {
	for _, c := range []struct{ ref, name, kind, version string }{
		{"node:16-bullseye", "node", "runtime", "16"},
		{"node:20.11.1-alpine3.19", "node", "runtime", "20.11.1"},
		{"docker.io/library/ruby:4.0.9-slim", "ruby", "runtime", "4.0.9"},
		{"python:3.8-slim@sha256:abc", "python", "runtime", "3.8"},
		{"public.ecr.aws/docker/library/python:3.12", "python", "runtime", "3.12"},
		{"golang:1.19", "go", "runtime", "1.19"},
		{"php:7.4-fpm", "php", "runtime", "7.4"},
		{"eclipse-temurin:11-jre", "java", "runtime", "11"},
		{"eclipse-temurin:21.0.1_12-jdk", "java", "runtime", "21.0.1"},
		{"openjdk:8u342-jre", "java", "runtime", "8"},
		{"amazoncorretto:17", "java", "runtime", "17"},
		{"mcr.microsoft.com/dotnet/aspnet:8.0", "dotnet", "runtime", "8.0"},
		{"gcr.io/distroless/nodejs20-debian12", "node", "runtime", "20"},
		{"gcr.io/distroless/java17-debian12:nonroot", "java", "runtime", "17"},
		{"postgres:12", "postgres", "database", "12"},
		{"postgis/postgis:15-3.4", "postgres", "database", "15"},
		{"redis:6.0-alpine", "redis", "database", "6.0"},
		{"mongo:4.4", "mongodb", "database", "4.4"},
		{"bitnami/postgresql:14.10.0", "postgres", "database", "14.10.0"},
		{"localhost:5000/node:18", "node", "runtime", "18"},
	} {
		r, ok := RuntimeFromImage(c.ref, "Dockerfile")
		if !ok || r.Name != c.name || r.Kind != c.kind || r.Version != c.version || r.SourceFile != "Dockerfile" {
			t.Errorf("%s: %+v %v, want %s %s %s", c.ref, r, ok, c.kind, c.name, c.version)
		}
	}
	for _, ref := range []string{"node", "node:latest", "node:lts-alpine", "python:alpine", "nginx:1.25", "myorg/api:1.2.3", "ruby:${RUBY}-slim", ""} {
		if r, ok := RuntimeFromImage(ref, "Dockerfile"); ok {
			t.Errorf("%s names no runtime version: %+v", ref, r)
		}
	}
}

func TestIsComposeFile(t *testing.T) {
	for p, want := range map[string]bool{
		"compose.yaml": true, "compose.yml": true, "docker-compose.yml": true, "ops/docker-compose.prod.yaml": true,
		"compose.override.yml": true, "docker-compose.json": false, "composer.json": false, "my-compose.yml": false,
	} {
		if IsComposeFile(p) != want || (want && !IsRuntimeFile(p)) {
			t.Errorf("%s: want %v", p, want)
		}
	}
}

// A Compose file's service images name their runtimes and databases; a service built from a
// Dockerfile, or an unknown image, names none.
func TestReadCompose(t *testing.T) {
	src := "services:\n  web:\n    build: .\n  db:\n    image: postgres:12\n  cache:\n    image: \"redis:6.0\"\n  proxy:\n    image: nginx:1.25\n  worker:\n    image: python:3.8-slim\n"
	rts, ok := ReadCompose("compose.yaml", []byte(src))
	if !ok || len(rts) != 3 {
		t.Fatalf("%+v %v", rts, ok)
	}
	got := map[string]string{}
	for _, r := range rts {
		got[r.Kind+" "+r.Name] = r.Version
		if r.SourceFile != "compose.yaml" {
			t.Errorf("source: %+v", r)
		}
	}
	if got["database postgres"] != "12" || got["database redis"] != "6.0" || got["runtime python"] != "3.8" {
		t.Fatalf("%v", got)
	}
	if _, ok := ReadCompose("compose.yaml", []byte("services: [unclosed")); ok {
		t.Fatal("a file that is not YAML is not read")
	}
}

// watchdep.yml's images name their runtimes too.
func TestConfigImagesNameRuntimes(t *testing.T) {
	cfg := &Config{Images: []string{"node:18-slim", "nginx:1.25"}, Path: FileName}
	rts := cfg.FromConfig()
	if len(rts) != 1 || rts[0].Name != "node" || rts[0].Version != "18" || rts[0].SourceFile != FileName {
		t.Fatalf("%+v", rts)
	}
}

// 16 from FROM node:16 and 16.20.0 from an .nvmrc are one release; 16 and 18, or 3.1 and 3.12, are not.
func TestConflictsCompareReleases(t *testing.T) {
	img, _ := RuntimeFromImage("node:16-bullseye", "Dockerfile")
	if cs := Conflicts(nil, append(ReadVersionFile(".nvmrc", []byte("16.20.0")), img)); len(cs) != 0 {
		t.Fatalf("one release: %+v", cs)
	}
	img18, _ := RuntimeFromImage("node:18", "Dockerfile")
	if cs := Conflicts(nil, append(ReadVersionFile(".nvmrc", []byte("16.20.0")), img18)); len(cs) != 1 {
		t.Fatalf("16 and 18 conflict: %+v", cs)
	}
	py, _ := RuntimeFromImage("python:3.1", "Dockerfile")
	if cs := Conflicts(nil, append(ReadVersionFile(".python-version", []byte("3.12.1")), py)); len(cs) != 1 {
		t.Fatalf("3.1 and 3.12.1 conflict: %+v", cs)
	}
}
