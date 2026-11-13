// Package codecheck searches the code where it is for imports and calls of each finding's package, and
// drafts a verdict: used, not used, or unclear. Only paths, line numbers and (when the workspace allows
// them) short snippets ever leave the machine.
package codecheck

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/kimathinjoki/depwatch-cli/internal/discover"
)

// Verdicts.
const (
	Used    = "used"
	NotUsed = "not_used"
	Unclear = "unclear"
)

// Place is where a finding's package sits in this part, as the server sends it.
type Place struct {
	Kind      string     `json:"kind"`
	Ecosystem string     `json:"ecosystem"`
	Name      string     `json:"name"`
	Version   string     `json:"version"`
	Relation  string     `json:"relation"`
	Paths     [][]string `json:"paths"`
}

// Finding is one open finding of the part.
type Finding struct {
	ID        int64    `json:"id"`
	PrimaryID string   `json:"primary_id"`
	Summary   string   `json:"summary"`
	Places    []Place  `json:"places"`
	Symbols   []string `json:"symbols"`
}

// Evidence is one line of code: a path relative to the part, a line number and what it shows.
type Evidence struct {
	Path    string `json:"path"`
	Line    int    `json:"line"`
	Note    string `json:"note"`
	Snippet string `json:"snippet,omitempty"`
}

// Result is the draft verdict for one finding.
type Result struct {
	FindingID int64      `json:"finding_id"`
	Verdict   string     `json:"verdict"`
	Reason    string     `json:"reason"`
	Evidence  []Evidence `json:"evidence"`
	Assisted  bool       `json:"assisted"`
	Model     string     `json:"model,omitempty"`
}

// MaxEvidence bounds the evidence sent per finding.
const MaxEvidence = 20

var languageFiles = map[string][]string{
	"npm":       {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"},
	"PyPI":      {".py"},
	"RubyGems":  {".rb", ".rake", ".ru"},
	"Go":        {".go"},
	"Maven":     {".java", ".kt", ".scala", ".groovy"},
	"Packagist": {".php"},
	"crates.io": {".rs"},
	"NuGet":     {".cs", ".fs", ".vb"},
	"Pub":       {".dart"},
	"Hex":       {".ex", ".exs"},
}

// buildDirs are build output and caches, never searched (installed dependencies are skipped by discover).
var buildDirs = map[string]bool{"dist": true, "build": true, "target": true, ".next": true, ".nuxt": true, "out": true, "coverage": true, "tmp": true, "log": true}

// sourceNames are source files with no extension, searched as their language.
var sourceNames = map[string]string{"Rakefile": ".rb", "Guardfile": ".rb", "Capfile": ".rb"}

// maxFile is the largest source file searched. A larger one is counted as not searched.
const maxFile = 1 << 20

// Code is the part's source files, read once.
type Code struct {
	Root  string
	files map[string][]string // path to lines
	byExt map[string][]string
	// skipped are source files of a searched language that could not be searched (too large,
	// unreadable, or a symbolic link), by extension: the search did not cover the code.
	skipped map[string][]string
	// gems are the gems the Gemfiles declare, with what Bundler requires for them.
	gems map[string]gemDecl
	// bundlerRequire is where Bundler.require loads every declared gem at boot.
	bundlerRequire []Evidence
	// pyInstalled and gemInstalled are import names read from installed packages in the part
	// (a virtual environment, vendor/bundle), by normalized package name.
	pyInstalled  map[string][]string
	gemInstalled map[string][]string
}

// gemDecl is what a Gemfile says Bundler requires for a gem: nothing (require: false), the paths
// named, or (neither) the gem's own name.
type gemDecl struct {
	noRequire bool
	paths     []string
}

// Load reads the part's source files (up to 1 MB each) for the ecosystems' languages, the Gemfiles'
// declarations, and the import names of packages installed in the part.
func Load(root string) (*Code, error) {
	want := map[string]bool{}
	for _, exts := range languageFiles {
		for _, e := range exts {
			want[e] = true
		}
	}
	c := &Code{Root: root, files: map[string][]string{}, byExt: map[string][]string{}, skipped: map[string][]string{},
		gems: map[string]gemDecl{}}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if p != root && (discover.SkippedDirs[d.Name()] || buildDirs[d.Name()]) {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.Name() == "Gemfile" || d.Name() == "gems.rb" {
			if d.Type().IsRegular() {
				if raw, err := os.ReadFile(p); err == nil {
					readGemfile(string(raw), c.gems)
				}
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(p))
		if e, ok := sourceNames[d.Name()]; ok {
			ext = e
		}
		if !want[ext] {
			return nil
		}
		if !d.Type().IsRegular() {
			c.skipped[ext] = append(c.skipped[ext], rel)
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() > maxFile {
			c.skipped[ext] = append(c.skipped[ext], rel)
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			c.skipped[ext] = append(c.skipped[ext], rel)
			return nil
		}
		c.files[rel] = strings.Split(string(raw), "\n")
		c.byExt[ext] = append(c.byExt[ext], rel)
		return nil
	})
	for _, list := range c.byExt {
		sort.Strings(list)
	}
	for _, file := range c.byExt[".rb"] {
		for i, line := range c.files[file] {
			if bundlerRequireRe.MatchString(line) {
				c.bundlerRequire = append(c.bundlerRequire, Evidence{Path: file, Line: i + 1, Note: "Bundler.require loads every gem the Gemfile declares"})
			}
		}
	}
	c.pyInstalled = pythonInstalled(root)
	c.gemInstalled = gemsInstalled(root)
	return c, err
}

var (
	bundlerRequireRe = regexp.MustCompile(`\bBundler\.require\b`)
	gemDeclRe        = regexp.MustCompile(`^\s*gem\s*\(?\s*["']([^"']+)["'](.*)$`)
	requireFalseRe   = regexp.MustCompile(`(?:\brequire:|:require\s*=>)\s*(?:false|nil)\b`)
	requirePathRe    = regexp.MustCompile(`(?:\brequire:|:require\s*=>)\s*["']([^"']+)["']`)
	requireAnyRe     = regexp.MustCompile(`(?:\brequire:|:require\s*=>)`)
)

// readGemfile records each gem line's require option. An option it cannot read (a list, a
// variable) leaves the gem as Bundler requires it by default.
func readGemfile(src string, into map[string]gemDecl) {
	for _, line := range strings.Split(src, "\n") {
		m := gemDeclRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		d := gemDecl{}
		switch {
		case requireFalseRe.MatchString(m[2]):
			d.noRequire = true
		case requirePathRe.MatchString(m[2]):
			d.paths = []string{requirePathRe.FindStringSubmatch(m[2])[1]}
		case requireAnyRe.MatchString(m[2]):
			d = gemDecl{} // an option it cannot read: as Bundler's default, the louder answer
		}
		if prev, ok := into[m[1]]; ok && !prev.noRequire && d.noRequire {
			continue // declared twice (two Gemfiles): one that Bundler requires stands
		}
		into[m[1]] = d
	}
}

// normPy folds a Python distribution name as PEP 503 does, with underscores.
func normPy(name string) string {
	return strings.ToLower(pyFoldRe.ReplaceAllString(name, "_"))
}

var pyFoldRe = regexp.MustCompile(`[-_.]+`)

// pythonInstalled reads the import names of the distributions installed in the part's virtual
// environment (.venv or venv): each one's top_level.txt, or else the top folders its RECORD lists.
func pythonInstalled(root string) map[string][]string {
	out := map[string][]string{}
	var metas []string
	for _, venv := range []string{".venv", "venv"} {
		for _, pattern := range []string{"lib/python*/site-packages/*.dist-info", "lib/python*/site-packages/*.egg-info", "Lib/site-packages/*.dist-info"} {
			m, _ := filepath.Glob(filepath.Join(root, venv, filepath.FromSlash(pattern)))
			metas = append(metas, m...)
		}
	}
	for _, meta := range metas {
		base := filepath.Base(meta)
		name := base
		if i := strings.Index(base, "-"); i > 0 {
			name = base[:i]
		}
		var mods []string
		if raw, err := os.ReadFile(filepath.Join(meta, "top_level.txt")); err == nil {
			for _, l := range strings.Fields(string(raw)) {
				mods = appendUnique(mods, strings.ReplaceAll(l, "/", "."))
			}
		} else if raw, err := os.ReadFile(filepath.Join(meta, "RECORD")); err == nil {
			for _, l := range strings.Split(string(raw), "\n") {
				f := strings.SplitN(strings.SplitN(l, ",", 2)[0], "/", 2)[0]
				if f == "" || strings.HasPrefix(f, "..") || strings.HasSuffix(f, ".dist-info") || strings.HasSuffix(f, ".data") ||
					strings.HasSuffix(f, ".pth") || f == "__pycache__" {
					continue
				}
				mods = appendUnique(mods, strings.TrimSuffix(f, ".py"))
			}
		}
		if len(mods) > 0 {
			out[normPy(name)] = mods
		}
	}
	return out
}

var gemDirRe = regexp.MustCompile(`^(.+?)-(\d[^-]*)(?:-.+)?$`)

// gemsInstalled reads the names each gem installed in vendor/bundle can be required by: the files
// and folders at the top of its lib folder.
func gemsInstalled(root string) map[string][]string {
	out := map[string][]string{}
	dirs, _ := filepath.Glob(filepath.Join(root, "vendor", "bundle", "ruby", "*", "gems", "*"))
	for _, dir := range dirs {
		m := gemDirRe.FindStringSubmatch(filepath.Base(dir))
		if m == nil {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(dir, "lib"))
		if err != nil {
			continue
		}
		var names []string
		for _, e := range entries {
			n := e.Name()
			if e.IsDir() {
				names = appendUnique(names, n)
			} else if strings.HasSuffix(n, ".rb") {
				names = appendUnique(names, strings.TrimSuffix(n, ".rb"))
			}
		}
		if len(names) > 0 {
			out[m[1]] = names
		}
	}
	return out
}

func (c *Code) filesFor(eco string) []string {
	var out []string
	for _, ext := range languageFiles[strings.Split(eco, ":")[0]] {
		out = append(out, c.byExt[ext]...)
	}
	sort.Strings(out)
	return out
}

func (c *Code) skippedFor(eco string) []string {
	var out []string
	for _, ext := range languageFiles[strings.Split(eco, ":")[0]] {
		out = append(out, c.skipped[ext]...)
	}
	sort.Strings(out)
	return out
}

// pyKnown are Python distributions whose import names are known, where they differ from the name.
var pyKnown = map[string][]string{
	"pyyaml": {"yaml"}, "python_multipart": {"multipart", "python_multipart"}, "beautifulsoup4": {"bs4"}, "pillow": {"PIL"},
	"scikit_learn": {"sklearn"}, "python_dateutil": {"dateutil"}, "opencv_python": {"cv2"}, "opencv_python_headless": {"cv2"},
	"opencv_contrib_python": {"cv2"}, "pyjwt": {"jwt"}, "python_jose": {"jose"}, "protobuf": {"google.protobuf"},
	"msgpack_python": {"msgpack"}, "django_rest_framework": {"rest_framework"}, "djangorestframework": {"rest_framework"},
	"pycryptodome": {"Crypto"}, "pycryptodomex": {"Cryptodome"}, "pycrypto": {"Crypto"}, "pyopenssl": {"OpenSSL"},
	"mysqlclient": {"MySQLdb"}, "psycopg2_binary": {"psycopg2"}, "attrs": {"attr", "attrs"}, "setuptools": {"setuptools", "pkg_resources"},
	"pyserial": {"serial"}, "python_ldap": {"ldap", "ldif", "ldapurl"}, "grpcio": {"grpc"}, "gitpython": {"git"}, "pygithub": {"github"},
	"python_dotenv": {"dotenv"}, "websocket_client": {"websocket"}, "pyzmq": {"zmq"}, "ipython": {"IPython"}, "pymongo": {"pymongo", "bson", "gridfs"},
	"python_socketio": {"socketio"}, "python_engineio": {"engineio"}, "flask_cors": {"flask_cors"}, "dnspython": {"dns"},
	"google_cloud_storage": {"google.cloud.storage"}, "pyasn1_modules": {"pyasn1_modules"}, "typing_extensions": {"typing_extensions"},
}

// pySame are Python distributions imported by their own name (folded), so a search that finds no
// import of them can say not used.
var pySame = map[string]bool{
	"requests": true, "urllib3": true, "django": true, "flask": true, "werkzeug": true, "jinja2": true, "markupsafe": true,
	"sqlalchemy": true, "numpy": true, "pandas": true, "scipy": true, "cryptography": true, "paramiko": true, "aiohttp": true,
	"tornado": true, "celery": true, "redis": true, "boto3": true, "botocore": true, "certifi": true, "idna": true, "lxml": true,
	"pyasn1": true, "rsa": true, "httpx": true, "starlette": true, "fastapi": true, "pydantic": true, "uvicorn": true,
	"gunicorn": true, "twisted": true, "mako": true, "markdown": true, "bleach": true, "babel": true, "tqdm": true, "click": true,
	"waitress": true, "gevent": true, "nltk": true, "transformers": true, "torch": true, "tensorflow": true, "keras": true,
	"mlflow": true, "pyarrow": true, "sentry_sdk": true, "httplib2": true, "oauthlib": true, "requests_oauthlib": true,
	"pymysql": true, "psycopg2": true, "psycopg": true, "jsonschema": true, "pygments": true, "feedparser": true,
	"ujson": true, "orjson": true, "simplejson": true, "six": true, "docker": true, "kombu": true, "gradio": true, "langchain": true,
}

// rubyKnown are gems whose require names are known, where they differ from the gem's name.
var rubyKnown = map[string][]string{"actionpack": {"action_controller", "action_dispatch"}, "activesupport": {"active_support"},
	"activerecord": {"active_record"}, "actionview": {"action_view"}, "activemodel": {"active_model"}, "activejob": {"active_job"},
	"actionmailer": {"action_mailer"}, "actioncable": {"action_cable"}, "activestorage": {"active_storage"}, "railties": {"rails"},
	"rest-client": {"rest-client", "restclient"}, "rails-html-sanitizer": {"rails-html-sanitizer", "rails/html/sanitizer"},
	"google-protobuf": {"google/protobuf"}}

// rubySame are gems required by their own name.
var rubySame = map[string]bool{
	"rack": true, "nokogiri": true, "puma": true, "json": true, "jwt": true, "pg": true, "mysql2": true, "sqlite3": true,
	"redis": true, "sidekiq": true, "httparty": true, "faraday": true, "oj": true, "bcrypt": true, "sinatra": true, "rake": true,
	"thor": true, "loofah": true, "rails": true, "devise": true, "omniauth": true, "net-imap": true, "net-smtp": true,
	"uri": true, "rexml": true, "psych": true, "erb": true, "mail": true, "addressable": true, "websocket-driver": true,
	"multi_json": true, "jbuilder": true, "kaminari": true, "pundit": true, "cancancan": true, "doorkeeper": true,
	"carrierwave": true, "paperclip": true, "rmagick": true, "mini_magick": true, "image_processing": true, "excon": true,
	"httpclient": true, "typhoeus": true, "sprockets": true, "sass": true, "haml": true, "slim": true, "liquid": true,
}

// modules gives the names a package is imported by, and whether they are known rather than guessed.
// A search that finds none of guessed names cannot say the package is not used.
func (c *Code) modules(eco, name string) ([]string, bool) {
	switch strings.Split(eco, ":")[0] {
	case "PyPI":
		n := normPy(name)
		if m, ok := c.pyInstalled[n]; ok {
			return m, true
		}
		if m, ok := pyKnown[n]; ok {
			return m, true
		}
		return []string{n}, pySame[n]
	case "RubyGems":
		var mods []string
		known := false
		if d, ok := c.gems[name]; ok && len(d.paths) > 0 {
			mods, known = append(mods, d.paths...), true
		}
		switch {
		case c.gemInstalled[name] != nil:
			mods, known = append(mods, c.gemInstalled[name]...), true
		case rubyKnown[name] != nil:
			mods, known = append(mods, rubyKnown[name]...), true
		default:
			mods = append(mods, name, strings.ReplaceAll(name, "-", "/"))
			known = known || rubySame[name]
		}
		return mods, known
	case "Maven":
		// The group id often is not the Java package (commons-collections is org.apache.commons.collections).
		if i := strings.Index(name, ":"); i > 0 {
			return []string{name[:i]}, false
		}
		return []string{name}, false
	case "Packagist":
		// The vendor is often, not always, the namespace; classes may be used fully qualified with no use line.
		if i := strings.Index(name, "/"); i > 0 {
			return []string{name[:i]}, false
		}
		return []string{name}, false
	case "crates.io":
		return []string{strings.ReplaceAll(name, "-", "_")}, true
	case "npm", "Go", "Pub":
		return []string{name}, true
	}
	return []string{name}, false
}

// importPattern matches a line importing one of the module names.
func importPattern(eco string, mods []string) *regexp.Regexp {
	alt := make([]string, len(mods))
	for i, m := range mods {
		alt[i] = regexp.QuoteMeta(m)
	}
	names := strings.Join(alt, "|")
	var expr string
	switch strings.Split(eco, ":")[0] {
	case "npm":
		expr = `(?:require\(\s*|import\s*\(\s*|from\s+|import\s+)['"](?:` + names + `)(?:/[^'"]*)?['"]`
	case "PyPI":
		expr = `^\s*(?:import\s+(?:` + names + `)(?:\.|\s|,|$)|from\s+(?:` + names + `)(?:\.\S*)?\s+import\b)`
	case "RubyGems":
		// require lines, and gem lines in a bundler/inline block, which require the gem
		expr = `\brequire(?:_relative)?\s*\(?\s*['"](?:` + names + `)(?:/[^'"]*)?['"]|^\s*gem\s+['"](?:` + names + `)['"]`
	case "Go":
		expr = `"(?:` + names + `)(?:/[^"]*)?"`
	case "Maven":
		expr = `^\s*import\s+(?:static\s+)?(?:` + names + `)\.`
	case "Packagist":
		expr = `(?i)^\s*use\s+\\?(?:` + names + `)\\`
	case "crates.io":
		expr = `\b(?:use|extern\s+crate)\s+(?:` + names + `)\b|\b(?:` + names + `)::`
	case "Pub":
		expr = `['"]package:(?:` + names + `)/`
	default:
		expr = `\b(?:` + names + `)\b`
	}
	return regexp.MustCompile(expr)
}

// Check drafts a verdict for one finding from the code alone.
func (c *Code) Check(f Finding) Result {
	r := Result{FindingID: f.ID, Evidence: []Evidence{}}
	var places []Place
	for _, p := range f.Places {
		if p.Kind == "package" {
			places = append(places, p)
		}
	}
	if len(places) == 0 {
		r.Verdict, r.Reason = Unclear, "The finding is in a runtime, a database or an operating system package, which the code check does not search."
		return r
	}
	var reasons []string
	verdict := ""
	for _, p := range places {
		files := c.filesFor(p.Ecosystem)
		if len(files) == 0 {
			reasons = append(reasons, fmt.Sprintf("No %s source files were found, so the use of %s could not be searched.", strings.Split(p.Ecosystem, ":")[0], p.Name))
			verdict = louder(verdict, Unclear)
			continue
		}
		mods, known := c.modules(p.Ecosystem, p.Name)
		imp := importPattern(p.Ecosystem, mods)
		var importing []string
		for _, file := range files {
			for i, line := range c.files[file] {
				if imp.MatchString(line) {
					r.add(Evidence{Path: file, Line: i + 1, Note: "imports " + p.Name})
					importing = appendUnique(importing, file)
				}
			}
		}
		calls := 0
		if len(f.Symbols) > 0 && len(importing) > 0 {
			sym := symbolPattern(f.Symbols)
			for _, file := range importing {
				for i, line := range c.files[file] {
					if m := sym.FindString(line); m != "" {
						calls++
						r.add(Evidence{Path: file, Line: i + 1, Note: "calls " + strings.TrimSpace(m)})
					}
				}
			}
		}
		switch {
		case calls > 0:
			verdict = louder(verdict, Used)
			reasons = append(reasons, fmt.Sprintf("%s is imported in %d %s, and the affected %s appear %d %s.", p.Name, len(importing), plural(len(importing), "file", "files"), plural(len(f.Symbols), "function", "functions"), calls, plural(calls, "time", "times")))
		case len(importing) > 0 && len(f.Symbols) > 0:
			verdict = louder(verdict, Unclear)
			reasons = append(reasons, fmt.Sprintf("%s is imported in %d %s, but none of the affected functions the advisory names (%s) appear; it may still reach them indirectly.", p.Name, len(importing), plural(len(importing), "file", "files"), strings.Join(f.Symbols, ", ")))
		case len(importing) > 0:
			verdict = louder(verdict, Used)
			reasons = append(reasons, fmt.Sprintf("%s is imported in %d %s; the advisory names no affected functions, so any use may reach the flaw.", p.Name, len(importing), plural(len(importing), "file", "files")))
		case p.Relation == "direct":
			// Not used only when the import names are known, the search covered the code, and
			// nothing loads the package without naming it. Otherwise the check cannot tell.
			lang := strings.Split(p.Ecosystem, ":")[0]
			skipped := c.skippedFor(p.Ecosystem)
			autoRequired := lang == "RubyGems" && len(c.bundlerRequire) > 0 && !c.gems[p.Name].noRequire
			switch {
			case autoRequired:
				verdict = louder(verdict, Unclear)
				r.add(c.bundlerRequire[0])
				reasons = append(reasons, fmt.Sprintf("No file requires %s, but %s:%d calls Bundler.require, which loads every gem the Gemfile declares (unless it says require: false), so the code may use it without a require line.", p.Name, c.bundlerRequire[0].Path, c.bundlerRequire[0].Line))
			case !known:
				verdict = louder(verdict, Unclear)
				reasons = append(reasons, fmt.Sprintf("%s is a direct dependency and no %s source file imports it as %s, but the name it is imported by is not known for certain, so its use could not be ruled out.", p.Name, lang, strings.Join(mods, " or ")))
			case len(skipped) > 0:
				verdict = louder(verdict, Unclear)
				reasons = append(reasons, fmt.Sprintf("No %s source file searched imports %s, but %d %s could not be searched (over 1 MB, unreadable or a symbolic link), for example %s.", lang, p.Name, len(skipped), plural(len(skipped), "file", "files"), skipped[0]))
			default:
				verdict = louder(verdict, NotUsed)
				reasons = append(reasons, fmt.Sprintf("%s is a direct dependency, but no %s source file searched imports it (as %s).", p.Name, lang, strings.Join(mods, " or ")))
			}
		default:
			verdict = louder(verdict, Unclear)
			via := "another package"
			if len(p.Paths) > 0 && len(p.Paths[0]) > 1 {
				via = strings.Join(p.Paths[0][:len(p.Paths[0])-1], " > ")
			}
			reasons = append(reasons, fmt.Sprintf("%s is not imported directly; it comes in through %s, which may use it.", p.Name, via))
		}
	}
	r.Verdict = verdict
	r.Reason = strings.Join(reasons, " ")
	return r
}

// louder keeps the verdict that hides least: used, then unclear, then not used.
func louder(a, b string) string {
	order := map[string]int{"": 0, NotUsed: 1, Unclear: 2, Used: 3}
	if order[b] > order[a] {
		return b
	}
	return a
}

func symbolPattern(symbols []string) *regexp.Regexp {
	alt := make([]string, 0, len(symbols))
	for _, s := range symbols {
		// "pkg.module.func" or "Type.Method": match the last segment as a whole word.
		last := s
		if i := strings.LastIndexAny(s, ".:#"); i >= 0 && i < len(s)-1 {
			last = s[i+1:]
		}
		alt = append(alt, regexp.QuoteMeta(last))
	}
	return regexp.MustCompile(`\b(?:` + strings.Join(alt, "|") + `)\b`)
}

func (r *Result) add(e Evidence) {
	if len(r.Evidence) < MaxEvidence {
		r.Evidence = append(r.Evidence, e)
	}
}

// Snippet returns the lines around one piece of evidence.
func (c *Code) Snippet(e Evidence, around int) string {
	lines := c.files[e.Path]
	from, to := e.Line-1-around, e.Line+around
	if from < 0 {
		from = 0
	}
	if to > len(lines) {
		to = len(lines)
	}
	var b strings.Builder
	for i := from; i < to; i++ {
		fmt.Fprintf(&b, "%d: %s\n", i+1, lines[i])
	}
	return b.String()
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func appendUnique(s []string, v string) []string {
	for _, x := range s {
		if x == v {
			return s
		}
	}
	return append(s, v)
}
