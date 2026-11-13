package image

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func readFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// --image with a local tarball lists its Debian packages with distribution and release.
func TestLocalTarball(t *testing.T) {
	layer, err := crane.Layer(map[string][]byte{
		"etc/os-release":      readFile(t, "../../testdata/fixtures/rootfs-debian/etc/os-release"),
		"var/lib/dpkg/status": readFile(t, "../../testdata/fixtures/rootfs-debian/var/lib/dpkg/status"),
	})
	if err != nil {
		t.Fatal(err)
	}
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := name.ParseReference("example.test/app:1")
	path := filepath.Join(t.TempDir(), "app.tar")
	if err := tarball.WriteToFile(path, ref, img); err != nil {
		t.Fatal(err)
	}
	res := ReadImage(context.Background(), path)
	if !res.Image.Read {
		t.Fatalf("not read: %s", res.Image.Reason)
	}
	if len(res.Packages) != 3 {
		t.Fatalf("want 3 packages, got %+v", res.Packages)
	}
	for _, p := range res.Packages {
		if p.Distribution != "Debian" || p.Release != "12" || p.Image != path {
			t.Fatalf("%+v", p)
		}
		if p.Name == "liblzma5" && p.SourceName != "xz-utils" {
			t.Fatalf("liblzma5 comes from the xz-utils source package: %+v", p)
		}
	}
}

// A fixture filesystem holding a Debian dpkg status file and an Alpine apk installed file lists
// their packages.
func TestFixtureFilesystems(t *testing.T) {
	deb, err := ReadFS(context.Background(), "../../testdata/fixtures/rootfs-debian", "rootfs-debian")
	if err != nil {
		t.Fatal(err)
	}
	if len(deb.Packages) != 3 || deb.Packages[0].Ecosystem != "Debian:12" {
		t.Fatalf("debian: %+v", deb.Packages)
	}
	alp, err := ReadFS(context.Background(), "../../testdata/fixtures/rootfs-alpine", "rootfs-alpine")
	if err != nil {
		t.Fatal(err)
	}
	if len(alp.Packages) != 2 {
		t.Fatalf("alpine: %+v", alp.Packages)
	}
	for _, p := range alp.Packages {
		if p.Distribution != "Alpine" || p.Name == "xz-libs" && p.SourceName != "xz" {
			t.Fatalf("%+v", p)
		}
	}
}

// An image that cannot be pulled or read is listed under not read.
func TestUnreadableImage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.tar")
	if err := os.WriteFile(path, []byte("not a tarball"), 0o644); err != nil {
		t.Fatal(err)
	}
	res := ReadImage(context.Background(), path)
	if res.Image.Read || res.Image.Reason == "" {
		t.Fatalf("%+v", res.Image)
	}
	res = ReadImage(context.Background(), "Not A Valid//Reference::")
	if res.Image.Read || res.Image.Reason == "" {
		t.Fatalf("%+v", res.Image)
	}
}

func TestFinalBase(t *testing.T) {
	for _, c := range []struct {
		src, want, unresolved string
		ok                    bool
	}{
		{"FROM node:20 AS build\nRUN npm ci\nFROM nginx:1.25-alpine\nCOPY --from=build /app /usr/share/nginx/html\n", "nginx:1.25-alpine", "", true},
		{"FROM ruby:3.3 AS base\nFROM base AS final\n", "ruby:3.3", "", true},
		{"ARG TAG\nFROM python:${TAG}\n", "python:${TAG}", "TAG", true},
		{"FROM golang:1.22 AS b\nFROM scratch\n", "", "", false},
		{"FROM --platform=linux/amd64 debian:12@sha256:abc\n", "debian:12@sha256:abc", "", true},
	} {
		b, ok := FinalBase(c.src)
		if ok != c.ok || b.Reference != c.want || b.Unresolved != c.unresolved {
			t.Errorf("%q: got %+v %v", c.src, b, ok)
		}
	}
}
