// Package image reads operating system packages from a container image or from a filesystem that
// holds a package database (an exported container filesystem, or a test fixture).
//
// Nothing in the image is run: the package databases are read as files.
package image

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/extractor"
	apkmeta "github.com/google/osv-scalibr/extractor/filesystem/os/apk/metadata"
	dpkgmeta "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	rpmmeta "github.com/google/osv-scalibr/extractor/filesystem/os/rpm/metadata"
	scalibrfs "github.com/google/osv-scalibr/fs"

	"github.com/kimathinjoki/watchdep-cli/internal/discover"
	"github.com/kimathinjoki/watchdep-cli/internal/extract"
	"github.com/kimathinjoki/watchdep-cli/internal/inventory"
)

// Result is what reading one image or filesystem gave.
type Result struct {
	Image        inventory.Image
	Packages     []inventory.OSPackage
	FilesRead    []inventory.FileRead
	FilesNotRead []inventory.FileNotRead
}

// ReadImage reads an image from a local tarball (docker save or an OCI archive) when ref names a
// file, else from its registry. An image that cannot be pulled or read is returned unread with the
// reason; it is never an empty, clean image.
func ReadImage(ctx context.Context, ref string) Result {
	res := Result{Image: inventory.Image{Reference: ref}}
	cfg := image.DefaultConfig()
	var img *image.Image
	var err error
	if st, statErr := os.Stat(ref); statErr == nil && !st.IsDir() {
		img, err = image.FromTarball(ref, cfg)
	} else {
		img, err = image.FromRemoteName(ref, cfg)
	}
	if err != nil {
		res.Image.Reason = "could not pull or open the image: " + oneLine(err.Error())
		return res
	}
	defer img.CleanUp()
	fsys := img.FS()
	files, err := discover.Walk(fsys, nil)
	if err != nil {
		res.Image.Reason = "could not list the image's files: " + oneLine(err.Error())
		return res
	}
	er, err := extract.OS(ctx, fsys, "/", relevant(files), ref)
	if err != nil {
		res.Image.Reason = err.Error()
		return res
	}
	res.fill(er, ref, "")
	if len(res.Packages) == 0 && len(res.FilesNotRead) == 0 {
		// An image with no package database is distroless or scratch: say so rather than read clean.
		res.Image.Reason = "no operating system package database found in the image"
		res.Image.Read = true
		return res
	}
	res.Image.Read = len(res.FilesNotRead) == 0
	if !res.Image.Read {
		res.Image.Reason = "a package database in the image could not be read"
	}
	return res
}

// ReadFS reads OS package databases in a folder laid out like a root filesystem.
func ReadFS(ctx context.Context, dir, label string) (Result, error) {
	res := Result{}
	st, err := os.Stat(dir)
	if err != nil || !st.IsDir() {
		return res, fmt.Errorf("%s is not a folder", dir)
	}
	fsys := scalibrfs.DirFS(dir)
	files, err := discover.Walk(fsys, nil)
	if err != nil {
		return res, err
	}
	er, err := extract.OS(ctx, fsys, dir, relevant(files), "")
	if err != nil {
		return res, err
	}
	res.fill(er, "", label)
	return res, nil
}

// relevant keeps the package database files, so an image's thousands of files are not each offered
// to every extractor.
func relevant(files []discover.File) []discover.File {
	var out []discover.File
	for _, f := range files {
		p := f.Path
		if strings.HasPrefix(p, "var/lib/dpkg/") || strings.HasPrefix(p, "lib/apk/db/") ||
			strings.HasPrefix(p, "var/lib/rpm/") || strings.HasPrefix(p, "usr/lib/sysimage/rpm/") ||
			strings.HasPrefix(p, "usr/lib/opkg/") || p == "etc/os-release" || p == "usr/lib/os-release" {
			out = append(out, f)
		}
	}
	return out
}

func (r *Result) fill(er *extract.Result, image, label string) {
	prefix := ""
	if label != "" {
		prefix = strings.TrimSuffix(label, "/") + "/"
	}
	for _, fr := range er.FilesRead {
		fr.Path = prefix + fr.Path
		if image != "" {
			fr.Path = image + ":" + fr.Path
		}
		r.FilesRead = append(r.FilesRead, fr)
	}
	for _, nr := range er.FilesNotRead {
		nr.Path = prefix + nr.Path
		if image != "" {
			nr.Path = image + ":" + nr.Path
		}
		r.FilesNotRead = append(r.FilesNotRead, nr)
	}
	for _, f := range er.Found {
		r.Packages = append(r.Packages, toOSPackage(f, image, prefix))
	}
	r.Image.Packages = len(r.Packages)
}

func toOSPackage(f extract.Found, image, prefix string) inventory.OSPackage {
	p := f.Pkg
	eco := p.Ecosystem()
	op := inventory.OSPackage{
		Distribution: string(eco.Ecosystem),
		Release:      eco.Suffix,
		Ecosystem:    eco.String(),
		Name:         p.Name,
		Version:      p.Version,
		SourceName:   p.Name,
		PURL:         purlString(p),
		SourceFile:   prefix + f.File,
		Image:        image,
	}
	switch m := p.Metadata.(type) {
	case *dpkgmeta.Metadata:
		if m.SourceName != "" {
			op.SourceName = m.SourceName
		}
		op.SourceVersion = m.SourceVersion
	case *apkmeta.Metadata:
		if m.OriginName != "" {
			op.SourceName = m.OriginName
		}
	case *rpmmeta.Metadata:
		if m.SourceRPM != "" {
			op.SourceName = rpmSourceName(m.SourceRPM)
		}
	}
	if op.SourceVersion == "" {
		op.SourceVersion = op.Version
	}
	return op
}

func purlString(p *extractor.Package) string {
	if u := p.PURL(); u != nil {
		return u.String()
	}
	return ""
}

// rpmSourceName takes "openssl-3.0.7-27.el9.src.rpm" and returns "openssl".
func rpmSourceName(src string) string {
	s := strings.TrimSuffix(src, ".src.rpm")
	for i := 0; i < 2; i++ {
		if j := strings.LastIndex(s, "-"); j > 0 {
			s = s[:j]
		}
	}
	return s
}

func oneLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}
