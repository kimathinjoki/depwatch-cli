package config

import "testing"

// A requirement names the release it is confined to; an open-ended one names none.
func TestRelease(t *testing.T) {
	for spec, want := range map[string]string{
		"16": "16", "16.20.0": "16.20.0", "v18.1": "18.1", "==3.11.4": "3.11.4", "16.x": "16", "3.11.*": "3.11",
		"^18.2.0": "18", "^7.4": "7", "^0.4.1": "0.4", "~16.2.0": "16.2", "~3": "3", "~> 3.3.0": "3.3", "~> 3.3": "3",
		"~=3.11.2": "3.11", "~=3.11": "3",
	} {
		if got, ok := Release(spec); !ok || got != want {
			t.Errorf("%q: %q %v, want %q", spec, got, ok, want)
		}
	}
	for _, spec := range []string{">=16", ">=3.8,<4", "^18 || ^20", "lts/iron", "*", "", "latest", "<4"} {
		if got, ok := Release(spec); ok {
			t.Errorf("%q is open-ended, got %q", spec, got)
		}
	}
}

// Each manifest, toolchain and build file names its runtime as projects write it.
func TestReadManifest(t *testing.T) {
	for _, c := range []struct{ file, src, name, version string }{
		{"package.json", `{"engines":{"node":"16.x"}}`, "node", "16"},
		{"composer.json", `{"require":{"php":"^7.4"}}`, "php", "7"},
		{"composer.json", `{"require":{"php":">=7.4"},"config":{"platform":{"php":"8.1.27"}}}`, "php", "8.1.27"},
		{"global.json", `{"sdk":{"version":"8.0.100","rollForward":"latestFeature"}}`, "dotnet", "8.0"},
		{"pyproject.toml", "[project]\nname = \"x\"\nrequires-python = \"==3.11.*\"\n", "python", "3.11"},
		{"pyproject.toml", "[tool.poetry.dependencies]\npython = \"~3.10\"\n", "python", "3.10"},
		{"Pipfile", "[requires]\npython_version = \"3.8\"\n", "python", "3.8"},
		{"runtime.txt", "python-3.8.10\n", "python", "3.8.10"},
		{"go.mod", "module x\n\ngo 1.19\n", "go", "1.19"},
		{"go.mod", "module x\n\ngo 1.21\n\ntoolchain go1.22.3\n", "go", "1.22.3"},
		{"Gemfile", "source \"https://rubygems.org\"\nruby \"3.2.2\"\ngem \"rails\"\n", "ruby", "3.2.2"},
		{"Gemfile", "ruby '~> 3.3.0'\n", "ruby", "3.3"},
		{"rust-toolchain", "1.75.0\n", "rust", "1.75.0"},
		{"rust-toolchain.toml", "[toolchain]\nchannel = \"1.76\"\n", "rust", "1.76"},
		{".java-version", "17.0.2\n", "java", "17.0.2"},
		{".java-version", "1.8\n", "java", "8"},
		{".java-version", "temurin-21\n", "java", "21"},
		{".sdkmanrc", "# sdk env\njava=11.0.21-tem\nmaven=3.9.6\n", "java", "11.0.21"},
		{"mise.toml", "[tools]\nnode = \"20\"\n", "node", "20"},
		{"pom.xml", "<project><properties><java.version>17</java.version><maven.compiler.target>1.8</maven.compiler.target></properties></project>", "java", "17"},
		{"pom.xml", "<properties><maven.compiler.source>1.8</maven.compiler.source></properties>", "java", "8"},
		{"build.gradle", "java {\n  toolchain {\n    languageVersion = JavaLanguageVersion.of(21)\n  }\n}\n", "java", "21"},
		{"build.gradle.kts", "kotlin {\n  jvmToolchain(17)\n}\n", "java", "17"},
		{"build.gradle", "sourceCompatibility = JavaVersion.VERSION_1_8\n", "java", "8"},
		{"build.gradle", "sourceCompatibility = '11'\n", "java", "11"},
	} {
		rts := ReadManifest(c.file, []byte(c.src))
		if len(rts) != 1 || rts[0].Name != c.name || rts[0].Version != c.version || rts[0].Kind != "runtime" || rts[0].SourceFile != c.file {
			t.Errorf("%s %q: %+v, want %s %s", c.file, c.src, rts, c.name, c.version)
		}
	}
	for _, c := range []struct{ file, src string }{
		{"package.json", `{"engines":{"node":">=16"}}`},
		{"package.json", `{"name":"x"}`},
		{"pyproject.toml", "[project]\nrequires-python = \">=3.8\"\n"},
		{"Gemfile", "ruby file: \".ruby-version\"\n"},
		{"rust-toolchain", "stable\n"},
		{"pom.xml", "<properties><java.version>${jdk}</java.version></properties>"},
		{"package.json", `{not json`},
	} {
		if rts := ReadManifest(c.file, []byte(c.src)); len(rts) != 0 {
			t.Errorf("%s %q names no release: %+v", c.file, c.src, rts)
		}
	}
}

// A Node LTS codename is its major release; a moving alias stays as written.
func TestNodeLTSAlias(t *testing.T) {
	for src, want := range map[string]string{"lts/iron\n": "20", "lts/Gallium": "16", "lts/*": "lts/*", "node": "node", "v20.11.1": "20.11.1"} {
		rts := ReadVersionFile(".nvmrc", []byte(src))
		if len(rts) != 1 || rts[0].Version != want {
			t.Errorf("%q: %+v, want %s", src, rts, want)
		}
	}
}
