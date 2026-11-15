package collect

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kimathinjoki/watchdep-cli/internal/inventory"
	"github.com/kimathinjoki/watchdep-cli/internal/testutil"
)

const monorepo = "../../testdata/fixtures/monorepo"

func take(t *testing.T, root string) *inventory.Inventory {
	t.Helper()
	inv, _, err := Take(context.Background(), Options{Root: root, CLIVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := inv.Validate(); err != nil {
		t.Fatalf("the inventory does not validate against the schema: %v", err)
	}
	return inv
}

func find(inv *inventory.Inventory, name string) *inventory.Package {
	for i := range inv.Packages {
		if inv.Packages[i].Name == name {
			return &inv.Packages[i]
		}
	}
	return nil
}

// A monorepo with a Rails app in api/ and a React app in client/ yields both ecosystems, each
// package tagged with the file it came from.
func TestMonorepoYieldsBothEcosystems(t *testing.T) {
	inv := take(t, monorepo)
	rack, react := find(inv, "rack"), find(inv, "react")
	if rack == nil || rack.Ecosystem != "RubyGems" || rack.SourceFile != "api/Gemfile.lock" {
		t.Fatalf("rack: %+v", rack)
	}
	if react == nil || react.Ecosystem != "npm" || react.SourceFile != "client/package-lock.json" {
		t.Fatalf("react: %+v", react)
	}
	if !inv.Complete() {
		t.Fatalf("the monorepo should be complete: %+v", inv.FilesNotRead)
	}
}

// .git, node_modules and vendor are not walked, nor any folder listed under ignore in watchdep.yml.
func TestSkippedFolders(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{"":{"dependencies":{"left-pad":"1"}},"node_modules/left-pad":{"version":"1.3.0"}}}`
	dir := testutil.Tree(t, map[string]string{
		"package.json":                     `{"dependencies":{"left-pad":"1"}}`,
		"package-lock.json":                lock,
		".git/package-lock.json":           lock,
		"node_modules/x/package-lock.json": lock,
		"vendor/y/composer.lock":           `{"packages":[{"name":"a/b","version":"1.0.0"}]}`,
		"legacy/package-lock.json":         lock,
		"legacy/package.json":              `{}`,
		"watchdep.yml":                     "ignore:\n  - legacy\n",
	})
	inv := take(t, dir)
	for _, f := range inv.FilesRead {
		for _, skipped := range []string{".git/", "node_modules/", "vendor/", "legacy/"} {
			if strings.HasPrefix(f.Path, skipped) {
				t.Errorf("%s was read; %s must not be walked", f.Path, skipped)
			}
		}
	}
	if len(inv.FilesRead) != 1 {
		t.Errorf("want only the root lockfile read, got %+v", inv.FilesRead)
	}
}

// A corrupt package-lock.json is listed under files not read, with the parser's reason, and the run
// is incomplete.
func TestCorruptLockfileIsNotRead(t *testing.T) {
	dir := testutil.Tree(t, map[string]string{
		"package.json":      `{"dependencies":{"a":"1"}}`,
		"package-lock.json": `{"lockfileVersion": 3, "packages": {`,
	})
	inv := take(t, dir)
	if len(inv.FilesNotRead) != 1 || inv.FilesNotRead[0].Path != "package-lock.json" || inv.FilesNotRead[0].Reason == "" {
		t.Fatalf("files not read: %+v", inv.FilesNotRead)
	}
	if inv.Complete() {
		t.Fatal("a corrupt lockfile must make the run incomplete")
	}
}

// A build.sbt (an ecosystem SCALIBR does not read) is listed as present and unsupported, and the run
// is incomplete.
func TestUnsupportedEcosystem(t *testing.T) {
	dir := testutil.Tree(t, map[string]string{"build.sbt": `libraryDependencies += "org.typelevel" %% "cats-core" % "2.9.0"`})
	inv := take(t, dir)
	if len(inv.Unsupported) != 1 || inv.Unsupported[0].Path != "build.sbt" {
		t.Fatalf("unsupported: %+v", inv.Unsupported)
	}
	if inv.Complete() {
		t.Fatal("an unsupported ecosystem must make the run incomplete")
	}
}

// A package.json with no lockfile beside it is listed as unpinned, its packages carry their declared
// ranges.
func TestUnpinnedPackageJSON(t *testing.T) {
	dir := testutil.Tree(t, map[string]string{
		"tools/package.json": `{"dependencies":{"express":"^4.18.0"},"devDependencies":{"jest":"~29.0.0"}}`,
	})
	inv := take(t, dir)
	if len(inv.Unpinned) != 1 || inv.Unpinned[0].Path != "tools/package.json" {
		t.Fatalf("unpinned: %+v", inv.Unpinned)
	}
	express, jest := find(inv, "express"), find(inv, "jest")
	if express == nil || express.Range != "^4.18.0" || express.Version != "" || express.Scope != inventory.ScopeProduction {
		t.Fatalf("express: %+v", express)
	}
	if jest == nil || jest.Range != "~29.0.0" || jest.Scope != inventory.ScopeDevelopment {
		t.Fatalf("jest: %+v", jest)
	}
}

// A workspace member's package.json is pinned by the lockfile at the top of the workspace.
func TestWorkspaceMemberIsNotUnpinned(t *testing.T) {
	dir := testutil.Tree(t, map[string]string{
		"package.json":            `{"workspaces":["packages/*"]}`,
		"package-lock.json":       `{"lockfileVersion":3,"packages":{"":{}}}`,
		"packages/a/package.json": `{"dependencies":{"left-pad":"^1.0.0"}}`,
	})
	inv := take(t, dir)
	if len(inv.Unpinned) != 0 {
		t.Fatalf("a workspace member is pinned by the root lockfile: %+v", inv.Unpinned)
	}
}

func TestDockerfileBaseImageIsListedNotRead(t *testing.T) {
	dir := testutil.Tree(t, map[string]string{
		"Dockerfile": "ARG RUBY=3.3\nFROM ruby:${RUBY}-slim AS build\nRUN bundle install\nFROM build AS final\n",
	})
	inv := take(t, dir)
	if len(inv.Images) != 1 || inv.Images[0].Reference != "ruby:3.3-slim" || inv.Images[0].Read {
		t.Fatalf("images: %+v", inv.Images)
	}
	if inv.Complete() {
		t.Fatal("an unpulled base image must make the inventory incomplete")
	}
}

const npmLock = `{"lockfileVersion":3,"packages":{"":{"dependencies":{"left-pad":"1"}},"node_modules/left-pad":{"version":"1.3.0"}}}`

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symbolic links are not available here: %v", err)
	}
}

// A lockfile that is a symbolic link to a file inside the project is read under the link's path.
func TestSymlinkInsideProjectIsRead(t *testing.T) {
	dir := testutil.Tree(t, map[string]string{
		"shared/locks/package-lock.json": npmLock,
		"watchdep.yml":                   "ignore:\n  - shared\n",
	})
	if err := os.MkdirAll(filepath.Join(dir, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	symlink(t, "../shared/locks/package-lock.json", filepath.Join(dir, "app", "package-lock.json"))
	inv := take(t, dir)
	lp := find(inv, "left-pad")
	if lp == nil || lp.SourceFile != "app/package-lock.json" {
		t.Fatalf("the linked lockfile was not read under its own path: %+v (read %+v)", lp, inv.FilesRead)
	}
	if !inv.Complete() {
		t.Fatalf("a link inside the project is read, not a gap: %+v", inv.FilesNotRead)
	}
}

// A lockfile that is a symbolic link leading outside the project is not followed: it is listed as
// not read, and the run is incomplete, never clean.
func TestSymlinkOutsideProjectIsNotRead(t *testing.T) {
	outside := testutil.Tree(t, map[string]string{"pom.xml": "<project></project>", "notes.txt": "x"})
	dir := testutil.Tree(t, map[string]string{"README.md": "hello"})
	symlink(t, filepath.Join(outside, "pom.xml"), filepath.Join(dir, "pom.xml"))
	symlink(t, filepath.Join(outside, "notes.txt"), filepath.Join(dir, "notes.txt"))
	inv := take(t, dir)
	if len(inv.FilesNotRead) != 1 || inv.FilesNotRead[0].Path != "pom.xml" || !strings.Contains(inv.FilesNotRead[0].Reason, "outside the project folder") {
		t.Fatalf("files not read: %+v", inv.FilesNotRead)
	}
	if inv.Complete() {
		t.Fatal("a dependency file not followed must make the run incomplete")
	}
}

// A folder that is a symbolic link leading outside the project is listed as not read, unless it is
// ignored in watchdep.yml or is a folder the walk never enters.
func TestSymlinkedFolderOutsideProject(t *testing.T) {
	outside := testutil.Tree(t, map[string]string{"package-lock.json": npmLock})
	dir := testutil.Tree(t, map[string]string{"watchdep.yml": "ignore:\n  - ignored\n"})
	symlink(t, outside, filepath.Join(dir, "linked"))
	symlink(t, outside, filepath.Join(dir, "ignored"))
	symlink(t, outside, filepath.Join(dir, "node_modules"))
	inv := take(t, dir)
	if len(inv.FilesNotRead) != 1 || inv.FilesNotRead[0].Path != "linked" || !strings.Contains(inv.FilesNotRead[0].Reason, "folder outside the project folder") {
		t.Fatalf("files not read: %+v", inv.FilesNotRead)
	}
}

// A dependency file that is a symbolic link to nothing is listed as not read.
func TestBrokenSymlinkIsNotRead(t *testing.T) {
	dir := testutil.Tree(t, map[string]string{})
	symlink(t, "missing/Gemfile.lock", filepath.Join(dir, "Gemfile.lock"))
	inv := take(t, dir)
	if len(inv.FilesNotRead) != 1 || inv.FilesNotRead[0].Path != "Gemfile.lock" {
		t.Fatalf("files not read: %+v", inv.FilesNotRead)
	}
}

// A --rootfs folder with no operating system package database in it was not a filesystem watchdep
// could check: it is listed as not read, and the run is incomplete.
func TestRootFSWithNoPackageDatabaseIsNotRead(t *testing.T) {
	dir := testutil.Tree(t, map[string]string{"go.mod": "module x\n\ngo 1.22\n"})
	empty := testutil.Tree(t, map[string]string{"etc/hostname": "box"})
	inv, _, err := Take(context.Background(), Options{Root: dir, RootFS: []string{empty}, CLIVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.FilesNotRead) != 1 || !strings.Contains(inv.FilesNotRead[0].Reason, "no operating system package database") {
		t.Fatalf("files not read: %+v", inv.FilesNotRead)
	}
	if inv.Complete() {
		t.Fatal("a root filesystem with nothing to read must make the run incomplete")
	}
}

// --rootfs does not stand in for the Dockerfile's base image: the base image is still listed (and
// pulled by gate), so an image nobody read never passes as clean.
func TestRootFSDoesNotHideBaseImages(t *testing.T) {
	dir := testutil.Tree(t, map[string]string{"Dockerfile": "FROM debian:12-slim\n"})
	inv, _, err := Take(context.Background(), Options{Root: dir, RootFS: []string{"../../testdata/fixtures/rootfs-debian"}, CLIVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Images) != 1 || inv.Images[0].Reference != "debian:12-slim" {
		t.Fatalf("images: %+v", inv.Images)
	}
	if len(inv.OSPackages) == 0 {
		t.Fatal("the root filesystem was not read")
	}
}
