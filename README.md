# watchdep-cli

`watchdep` is a command line tool that takes the inventory of a project (every package at every
depth, with the path that brought it in and whether it ships to production, the runtimes, and the
operating system packages of its images) and checks it for known vulnerabilities and compromised
releases. It runs where the code already is, on a developer's machine or in CI, and needs no
watchdep server.

It is the open part of watchdep. On its own it fails a CI build on what is exploited now, with no
account. With the watchdep service, `scan` sends the inventory (never the code) so findings are kept
across applications until a person decides them. The GitHub Action
[`watchdep-action`](https://github.com/kimathinjoki/watchdep-action) runs it in CI.

The rule it never breaks: **nothing reads as clean when watchdep did not look.** A file it could not
read, an ecosystem it does not support, an image it could not pull or a source that did not answer
is shown, and makes the run incomplete, with its own exit code.

## Install

Releases are one static binary per platform (Linux, macOS and Windows, on amd64 and arm64), with a
checksums file, on the [releases page](https://github.com/kimathinjoki/watchdep-cli/releases).
Download the archive for your platform and `checksums.txt`, check it and put `watchdep` on your path:

```sh
v=0.3.0
curl -fsSLO "https://github.com/kimathinjoki/watchdep-cli/releases/download/v$v/watchdep_${v}_linux_amd64.tar.gz"
curl -fsSLO "https://github.com/kimathinjoki/watchdep-cli/releases/download/v$v/checksums.txt"
sha256sum --check --ignore-missing checksums.txt
tar -xzf "watchdep_${v}_linux_amd64.tar.gz" watchdep
./watchdep version
```

Or build it from source with Go 1.27 or later:

```sh
git clone https://github.com/kimathinjoki/watchdep-cli
cd watchdep-cli
make build            # writes bin/watchdep
./bin/watchdep version
```

## Commands

### `watchdep inventory [path]`

Lists everything the project contains, and everything that could not be read. Makes no network call.

```text
$ watchdep inventory
watchdep inventory  storefront  main 3f2c1a9

Not read (1)
  client/package-lock.json
    javascript/packagelockjson could not read it: unexpected end of JSON input

Packages
  api                          RubyGems   Gemfile.lock              212  (171 production, 41 development)
  client                       npm        package-lock.json         884  (402 production, 482 development)

Runtimes  (listed, not yet checked)
  ruby       3.3.4          runtime   api/.ruby-version
  node       20.11.1        runtime   client/.nvmrc

1096 packages from 2 files. Incomplete: some of what was found could not be read.
```

What was not read always comes first, in deep orange. `--json` writes the inventory exactly as
[`schema/inventory.schema.json`](schema/inventory.schema.json) defines it; this is the shape the
watchdep server accepts.

Symbolic links: a link to a file inside the project is read under the link's own path, and a link to
a folder inside it is not entered twice (the folder is walked under its own path). A link that leads
outside the project, or nowhere, is never followed; when it is a folder, or a file watchdep would read
(a dependency file, a Dockerfile, a version file), it is listed as not read and the run is incomplete.

Flags: `--image <ref>` reads a container image (a local tarball from `docker save` or an OCI archive,
or a registry reference); `--rootfs <dir>` reads the package databases in a folder laid out like a
root filesystem (a folder with no package database in it is listed as not read, and the run is
incomplete). Both may be repeated.

Exit codes: `0` everything found was read; `2` incomplete; `3` a usage or `watchdep.yml` error.

### `watchdep gate [path]`

Takes the inventory, checks it against OSV, CISA KEV and EPSS, ranks every finding, and exits
non-zero when one meets the threshold, so a CI build can stop on it.

```text
$ watchdep gate
watchdep gate  billing  main 50246b7

SEVERE  CVE-2021-44228  GHSA-jfh8-c2jp-5v3q  [fails the gate]
  Remote code injection in Log4j
  exploited now
  production, in CISA KEV since 2021-12-10, EPSS 100.0%, CVSS 10.0
  why: listed in CISA KEV: exploited now
  org.apache.logging.log4j:log4j-core 2.14.1  pom.xml  production
    org.apache.logging.log4j:log4j-core
    fix: 2.15.0

HIGH  CVE-2021-44832  GHSA-8489-44mv-ggj8
  Improper Input Validation and Injection in Apache Log4j2
  production, EPSS 97.9%, CVSS 6.6
  why: medium (CVSS 6.6) raised by EPSS 97.9%
  ...

2 severe, 2 high, 4 medium. Failing on: kev, malicious.
Failed: 2 finding(s) meet the threshold: CVE-2021-44228, CVE-2021-45046.
```

When OSV names an advisory for a package but its details cannot be fetched, the advisory is kept, never
dropped: a `MAL-` id alone is a severe malicious finding, and any other id is a finding labelled
provisional (ranked as one with no severity stated). OSV's error is shown and the run is incomplete.

`--fail-on` takes any of:

| Value | Fails on |
|---|---|
| `malicious` | a malicious release, in any scope (its install scripts already ran) |
| `kev` | listed in CISA KEV (exploited now), in production scope |
| `severe` | level severe, provisional included |
| `high` | level high or severe |

The default is `--fail-on malicious,kev`. Other flags: `--allow-incomplete` (exit 0 rather than 2
when the check is incomplete and nothing meets the threshold), `--epss-threshold 0.10` (the EPSS
probability at or above which a critical finding is severe), `--image`, `--rootfs`, `--json`.

A folder with no dependency files at all (for example a CI job that never checked the code out) is
not clean: `gate` says "No dependency files found in this folder. Nothing was checked; this is not a
clean result." and exits 2.

`gate` pulls base images named in `watchdep.yml` or a Dockerfile's final stage, unless `--image`
already gave it the built image. `--rootfs` does not stand in for base images (nothing says which image
a folder came from), so they are still pulled. A base image it cannot pull makes the run incomplete.

### `watchdep scan [path]`

Sends the project's inventory to a watchdep server. Only the inventory leaves the machine; the code
never does.

```sh
export WATCHDEP_SERVER=https://watchdep.example.com
export WATCHDEP_TOKEN=wdp_...      # created on the part's Tokens page, shown once
watchdep scan
```

The server and token come from `--server` and `--token`, else `WATCHDEP_SERVER` and `WATCHDEP_TOKEN`,
else the `watchdep login` of the folder or the nearest folder above it. Exit codes: `0` sent; `2` the server did not answer, or did not look (a hosted plan's scans for today are used; the server's reason is printed); `3` no token, a
refused token, or an inventory the server rejected.

### `watchdep check [path]`

Checks whether the code uses each open finding's package, and sends draft verdicts (used, not used,
unclear) with evidence as file paths and line numbers to the server. A verdict never closes a finding;
a person decides.

```sh
watchdep check                 # with WATCHDEP_SERVER and WATCHDEP_TOKEN, as scan
watchdep check --dry-run       # print the verdicts, send nothing
watchdep check --assist        # have a model draft each verdict, with your own key
watchdep check --assist --provider google --model gemini-4-argon
watchdep models --provider openai   # the models --assist can use with that provider
```

"Not used" is drafted only when the check can be sure: the package is a direct dependency, the names
it is imported by are known (npm, Go, Rust and Dart by their own rules; Python and Ruby from the
packages installed in the part's `.venv` or `vendor/bundle`, or from a list of known names; never for
Maven, Composer, NuGet or Hex, whose import names cannot be told from the package name), every source
file of its language was searched, and, for Ruby, no `Bundler.require` loads the gem at boot (unless
the Gemfile says `require: false`). Otherwise the verdict is unclear, with the reason.

Code leaves the machine only as a few lines around each piece of evidence, and only when the workspace
owner allowed snippets. With `--assist`, the evidence and the lines around it go to the provider you
choose, from this machine with your own key; the watchdep server never sees the key or the code.

| `--provider` | Key | Default `--model` |
|---|---|---|
| `anthropic` | `ANTHROPIC_API_KEY`, or your Anthropic login | `claude-opus-5-5` |
| `google` | `GEMINI_API_KEY` | `gemini-4-carbon` |
| `openai` | `OPENAI_API_KEY` | none: name one (`watchdep models --provider openai`) |

Without `--provider`, the first key set in that order chooses. The assistant may sharpen a verdict and
its reason, but never turns a found use into "not used"; a refusal, an error or an answer in the wrong
form keeps the search's verdict and says why. Google and OpenAI are asked to keep no copy of the
request.

### `watchdep fix [path]`

Run in the project's own CI (`watchdep-action` does it). For each finding the workspace set to be fixed
by pull request, it upgrades the package with the project's own package manager (npm, yarn, pnpm, bun,
Composer, Bundler, pip requirements, poetry, uv, pipenv, Go modules, Cargo; Dockerfile base images pinned
by digest), using the package manager's override for a package that comes in through another, takes
the inventory again to check the fix version is reached (otherwise it puts the files back and names the
fix), and opens one pull request per finding per part with `GITHUB_TOKEN`, or updates the open one. It
never merges. `--dry-run` shows the changes and puts the files back.

What the server sends is checked before anything runs: a source file outside the repository (after
following symbolic links), a package name that is not one of its ecosystem's or starts with `-`, and a
fix that is not a plain version (no range, URL or `github:` spec) are refused and the fix named. Direct
upgrades pin the exact fix version. npm, yarn, pnpm and bun run with install scripts off, Composer with
scripts and plugins off, and every package manager gets a minimal environment: `PATH`, `HOME`, proxies,
certificates and its own settings, but never a variable that looks like a credential (`GITHUB_TOKEN`,
`WATCHDEP_TOKEN`, `NODE_AUTH_TOKEN` and the like), so a private registry needs its credentials in the
package manager's own configuration file. A package no longer found in its file after the change is not
a verified fix. A base image moved to a new digest is read again to check it carries the fixed
operating system package; below the fix, the Dockerfile is put back; when the new image cannot be read,
the pull request says plainly that the fix is not verified.

### `watchdep deployed --sha <commit>`

Reports a deployment from the deploy step, so production is what was deployed. Run `watchdep scan` in
the same step so the deployed commit has an inventory.

### `watchdep login [path] --server <url> --token <token>`

Stores a part's token for the part's folder (the path given, or the current folder) in your config
folder (`~/.config/watchdep/credentials.json` on Linux, readable only by you). `scan`, `check`, `fix`
and `deployed` in that folder, or a folder inside it, use it. Each part's folder needs its own login,
so two projects on one machine never send under each other's token:

```sh
cd ~/code/shop-api    && watchdep login --server https://app.watchdep.com --token wdp_...
cd ~/code/shop-client && watchdep login --server https://app.watchdep.com --token wdp_...
```

Logins from 0.1.0, one per server, are no longer used: run `watchdep login` again in each part's folder.

### `watchdep mirror sync` and `watchdep mirror status`

Keep a local copy of OSV for matching with no network per package:

```sh
watchdep mirror sync --dir ~/osv --ecosystem npm --ecosystem RubyGems
watchdep mirror status --dir ~/osv
watchdep gate --mirror ~/osv          # gate against the mirror instead of the OSV API
```

An unchanged export is not downloaded again; a failed download keeps the previous copy. `gate --mirror`
still answers from that copy, but an ecosystem whose last sync failed, or whose last good sync is over
24 hours old, is listed as a stale source and the run is incomplete. For a machine
with no route to OSV, download `https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`
elsewhere and install it with `--archive all.zip` (one ecosystem at a time).

### `watchdep match --mirror <dir> --inventory <file>`

Reads an inventory file and answers, from a mirror, which advisories
affect each package, with each advisory's entry, facts (CVSS score, source severity, malicious, CVEs)
and fix versions. It does no ranking. You will rarely run it yourself.

### `watchdep version`

Prints the version, commit and build date stamped at build time.

### `watchdep reference`

Hidden from `--help`: writes the whole command line (every command, flag, default, the exit codes and
the environment variables) as JSON. The public site's docs are generated from it, so they say exactly
what `--help` says.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Nothing meets the threshold and the check is complete |
| 1 | A finding meets the threshold. Wins over incomplete. |
| 2 | Incomplete: something could not be read or checked, or a source did not answer. 0 instead with `--allow-incomplete` when nothing meets the threshold. |
| 3 | A usage or `watchdep.yml` error, including a path that does not exist or is not a folder |

Every command accepts `--json`, which switches all output, errors included, to JSON. Colour is used
only when the output is a terminal, and `NO_COLOR` turns it off.

## Configure: `watchdep.yml`

An optional file at the root of the project for what no lockfile states. Every key is optional; an
unknown key or a wrong type stops the run with exit code 3 and names the line. The annotated example
is [`examples/watchdep.yml`](examples/watchdep.yml); the schema is
[`schema/watchdep.schema.json`](schema/watchdep.schema.json).

```yaml
version: 1
production_branch: main
runtimes:
  ruby: "3.3.4"
  node: "20.11.1"
databases:
  - engine: postgres
    version: "16"
hosting:
  - name: heroku-stack
    version: "24"
images:
  - ruby:3.3.4-slim-bookworm
ignore:
  - docs/
```

Runtimes and databases also come from where projects already state them:

- version files: `.ruby-version`, `.nvmrc`, `.node-version`, `.python-version`, `.tool-versions`,
  `mise.toml`, `.java-version`, `.sdkmanrc`, `runtime.txt`, `rust-toolchain(.toml)`, `global.json`;
- manifests and build files: `package.json` `engines.node`, `pyproject.toml` `requires-python` (or
  Poetry's `python`), `Pipfile`, `go.mod` (`toolchain`, else `go`), `composer.json` (`config.platform.php`,
  else `require.php`), the `Gemfile`'s `ruby`, and Java's release in `pom.xml` and Gradle builds;
- images: the final stage of each Dockerfile (`FROM node:16-bullseye` is node 16; a build stage does
  not ship, so it is not listed), the images in `watchdep.yml`, and each service's `image` in Compose
  files (`postgres:12` is postgres 12). Official images, the common Java builds (Temurin, Corretto,
  OpenJDK), .NET, distroless and Bitnami images are known.

A range names the release it is confined to (`^18.2.0` is 18, `~> 3.3.0` is 3.3, `16.x` is 16); an
open-ended one such as `>=16` names none, as production could run any version it allows. A Node LTS
codename (`lts/iron`) is its major release. When two sources in the same folder name different
releases, both are listed and the output says they disagree; `16` and `16.20.0` agree. The gate lists runtimes without checking them (the output says so);
a watchdep server checks them against NVD and endoflife.date.

## In CI

```yaml
# .github/workflows/watchdep.yml
name: watchdep
on: [push, pull_request]
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Build the image
        run: docker build -t app:ci . && docker save app:ci -o app.tar
      - uses: kimathinjoki/watchdep-action@65e91e5a703f944e8c027a3af5333cf63b6fdefe   # v1.1.0, pinned by commit SHA
        with:
          version: 0.3.0
          command: gate
          args: --image app.tar --fail-on malicious,kev,severe
```

[`watchdep-action`](https://github.com/kimathinjoki/watchdep-action) installs a release whose checksums
it carries (its `version` input is required), checks the download against them and runs the command.

Reading the built image (`--image app.tar`) checks the operating system packages production will
actually run.

## What it reads

Every lockfile OSV-SCALIBR reads: npm, yarn, pnpm and bun; Composer; Bundler; pip, poetry, uv,
pipenv and pdm; Go modules; Cargo; Maven and Gradle; NuGet; Pub; Mix; Swift Package Manager and
CocoaPods; and more. Dependency paths and scope are read from the lockfile itself for Bundler, npm,
yarn, pnpm, Composer, poetry, uv, Cargo and NuGet; for other files the path reads "path not
recorded" and scope comes from what the file says, or production (the louder answer) when it says
nothing. Operating system packages are read from Debian, Ubuntu, Alpine and Red Hat family package
databases.

## Settings

The CLI reads its settings from the environment (or flags). `.env.example` lists every variable it
reads, commented, with what it is for; export them in your shell or set them as CI secrets. It does not
read a `.env` file itself.

## Build and test

```sh
make build      # bin/watchdep, stamped with the git version
make test       # unit tests and the known incidents corpus, offline, with the race detector
make lint       # gofmt, go vet, staticcheck
make live       # the corpus against the real sources (network), reporting any drift
make snapshot   # six release binaries and checksums in dist/, checked; nothing is published
```

To release, tag `main` (`git tag v0.1.0 && git push origin v0.1.0`). The release workflow runs the
suite, then publishes the binaries and `checksums.txt` as a GitHub release. Copy that `checksums.txt`
into `watchdep-action` as `checksums/<version>.txt` so the Action can install it.

No test reaches the network by default. Source answers are recorded under `testdata/`; the `live`
build tag re-runs the corpus against the real sources. To refresh the recordings after a reviewed
change: `go test -tags live ./internal/corpus -run TestCorpusLive -update`, then review the diff of
every `expected.json`.

The known incidents corpus (`testdata/corpus/`) holds real cases: Log4Shell, rack in a Rails
lockfile, the event-stream and ua-parser-js compromises, the xz backdoor in a Debian filesystem, a
Django lockfile, a critical advisory with no EPSS score, a development-only critical, a corrupt
lockfile with an unsupported file, and a stalled source. A change that drops one fails the build.

The ranking rules are every case in `testdata/ranking_cases.json`; the watchdep service is tested
against the same cases, so both rank alike.

## Licence

MIT. Copyright 2026 kimathinjoki.
