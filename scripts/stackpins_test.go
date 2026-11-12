package scripts_test

// VZ-FOUND-001 / VZ-FOUND-004 (search part): the lockfile and the Go toolchain
// and module pins must match meta docs/adr/ADR-001-stack-pins-and-licences.md,
// and every actions/setup-go step must resolve EXACTLY the pinned toolchain.
//
// Meta #32 verifier F-1: a setup-go reading `go-version-file: go.mod` with a
// setup-go that takes the `go` directive installs go1.26.0, not the
// `toolchain go1.27.4` pin. So the only accepted sources here are an exact
// `go-version: 1.27.4` (directly or through a workflow/job `env` value) or
// `go-version-file: go.mod`; anything else — a range, `stable`, another file,
// no version at all — is refused.
//
// Pins are copied from ADR-001; change both together. Modules in go.mod with
// no ADR-001 row are listed in ADRUnlisted (reported to the chair, not
// silently accepted): a new direct dependency fails until it is classified.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	pinGoLine    = "1.26.0" // go.mod language floor
	pinToolchain = "1.27.4" // ADR-001 "Go toolchain | 1.27.x (1.27.4)"
)

var reVer = regexp.MustCompile(`\d+`)

func semver(v string) [3]int {
	var out [3]int
	for i, s := range reVer.FindAllString(v, 3) {
		fmt.Sscan(s, &out[i])
	}
	return out
}

// adrModules: module -> (ADR-001 row, predicate).
var adrModules = map[string]struct {
	row string
	ok  func(v string) bool
}{
	"github.com/labstack/echo/v5": {"echo/v5 >= v5.4.4", func(v string) bool {
		s := semver(v)
		return s[0] == 5 && (s[1] > 4 || (s[1] == 4 && s[2] >= 4))
	}},
	"github.com/redis/go-redis/v9":     {"go-redis/v9 v9.22.x", func(v string) bool { s := semver(v); return s[0] == 9 && s[1] == 22 }},
	"github.com/davidbyttow/govips/v2": {"govips/v2 v2.18.0", func(v string) bool { return semver(v) == [3]int{2, 18, 0} }},
}

// Direct dependencies with NO ADR-001 row. Reported as a missing ADR row;
// listing one here is a reviewed diff.
var adrUnlisted = map[string]bool{"gopkg.in/yaml.v3": true}

var envRef = regexp.MustCompile(`^\$\{\{\s*env\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}$`)

type wfStep struct {
	Uses string            `yaml:"uses"`
	With map[string]string `yaml:"with"`
	Env  map[string]string `yaml:"env"`
}
type wfJob struct {
	Env   map[string]string `yaml:"env"`
	Steps []wfStep          `yaml:"steps"`
}
type workflow struct {
	Env  map[string]string `yaml:"env"`
	Jobs map[string]wfJob  `yaml:"jobs"`
}

// checkStackPins returns every violation in the tree at root.
func checkStackPins(root string) []string {
	var errs []string
	if fi, err := os.Stat(filepath.Join(root, "go.sum")); err != nil || fi.Size() == 0 {
		errs = append(errs, "go.sum is missing or empty: the lockfile must be committed")
	}
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return append(errs, "go.mod is missing")
	}
	gomod := string(b)
	if m := regexp.MustCompile(`(?m)^go\s+(\S+)\s*$`).FindStringSubmatch(gomod); m == nil || m[1] != pinGoLine {
		errs = append(errs, fmt.Sprintf("go.mod `go` line is %v, want %s", m, pinGoLine))
	}
	if m := regexp.MustCompile(`(?m)^toolchain\s+go(\S+)\s*$`).FindStringSubmatch(gomod); m == nil {
		errs = append(errs, "go.mod `toolchain` line is absent, want go"+pinToolchain+" (ADR-001)")
	} else if m[1] != pinToolchain {
		errs = append(errs, fmt.Sprintf("go.mod `toolchain` line is go%s, want go%s (ADR-001)", m[1], pinToolchain))
	}
	// Every required module, direct or indirect.
	for _, m := range regexp.MustCompile(`(?m)^\s*(?:require\s+)?([a-z0-9][^\s()]*\.[^\s()]+)\s+(v\S+)(\s*//\s*indirect)?`).FindAllStringSubmatch(gomod, -1) {
		mod, ver, indirect := m[1], m[2], m[3] != ""
		if mod == "module" {
			continue
		}
		if a, ok := adrModules[mod]; ok {
			if !a.ok(ver) {
				errs = append(errs, fmt.Sprintf("%s is %s, ADR-001 row says %s", mod, ver, a.row))
			}
		} else if !indirect && !adrUnlisted[mod] {
			errs = append(errs, fmt.Sprintf("%s %s is a direct dependency with no ADR-001 row and is not in adrUnlisted", mod, ver))
		}
	}
	if !strings.Contains(gomod, "github.com/labstack/echo/v5 ") {
		errs = append(errs, "github.com/labstack/echo/v5 not in go.mod (ADR-001 row: echo/v5 >= v5.4.4)")
	}
	// Workflows: every setup-go resolves exactly the pin.
	wfs, _ := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.y*ml"))
	sort.Strings(wfs)
	seen := 0
	for _, path := range wfs {
		raw, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		var wf workflow
		if err := yaml.Unmarshal(raw, &wf); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", filepath.Base(path), err))
			continue
		}
		for jn, job := range wf.Jobs {
			for _, st := range job.Steps {
				if !strings.HasPrefix(st.Uses, "actions/setup-go@") {
					continue
				}
				seen++
				where := fmt.Sprintf("%s job %s", filepath.Base(path), jn)
				v, hasV := st.With["go-version"]
				f, hasF := st.With["go-version-file"]
				switch {
				case hasV && hasF, !hasV && !hasF:
					errs = append(errs, fmt.Sprintf("%s: setup-go must set exactly one of go-version / go-version-file", where))
				case hasF:
					if f != "go.mod" {
						errs = append(errs, fmt.Sprintf("%s: setup-go reads go-version-file %q; want go.mod or go-version %s", where, f, pinToolchain))
					}
				default:
					if m := envRef.FindStringSubmatch(v); m != nil {
						r, ok := st.Env[m[1]]
						if !ok {
							r, ok = job.Env[m[1]]
						}
						if !ok {
							r, ok = wf.Env[m[1]]
						}
						if !ok {
							errs = append(errs, fmt.Sprintf("%s: setup-go go-version %s is undefined", where, v))
							continue
						}
						v = r
					}
					if v != pinToolchain {
						errs = append(errs, fmt.Sprintf("%s: setup-go go-version %q; want exactly %s (ADR-001)", where, v, pinToolchain))
					}
				}
				if cl := st.With["check-latest"]; cl == "true" {
					errs = append(errs, where+": setup-go check-latest: true can drift off the pin")
				}
			}
		}
	}
	if seen == 0 {
		errs = append(errs, "no actions/setup-go step found in .github/workflows: nothing proves the CI toolchain")
	}
	// Dockerfile build stage is digest-pinned to the ADR toolchain image.
	if df, err := os.ReadFile(filepath.Join(root, "Dockerfile")); err == nil {
		errs = append(errs, checkDockerBuildStage(string(df))...)
	}
	sort.Strings(errs)
	return errs
}

// dockerPinnedGoRe is the only accepted build-stage image: the ADR toolchain
// tag (so the Go version is readable) plus the image-index digest (so the
// bytes are pinned), e.g. golang:1.27.4-bookworm@sha256:<64 hex>.
var dockerPinnedGoRe = regexp.MustCompile(`^(?:docker\.io/)?(?:library/)?golang:` +
	regexp.QuoteMeta(pinToolchain) + `-[a-z0-9][a-z0-9.]*@sha256:[0-9a-f]{64}$`)

// checkDockerBuildStage parses FROM instructions (comments and other lines
// ignored, --flags skipped) and requires the stage named "build" to exist,
// be unique, and use the pinned Go image.
func checkDockerBuildStage(df string) []string {
	var errs []string
	builds := 0
	for _, line := range strings.Split(df, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || !strings.EqualFold(f[0], "FROM") {
			continue
		}
		args := f[1:]
		for len(args) > 0 && strings.HasPrefix(args[0], "--") {
			args = args[1:]
		}
		if len(args) != 3 || !strings.EqualFold(args[1], "AS") || !strings.EqualFold(args[2], "build") {
			continue
		}
		builds++
		if !dockerPinnedGoRe.MatchString(args[0]) {
			errs = append(errs, fmt.Sprintf("Dockerfile build stage image %q is not golang:%s-<variant>@sha256:<digest>", args[0], pinToolchain))
		}
	}
	if builds != 1 {
		errs = append(errs, fmt.Sprintf("Dockerfile build stage: want exactly one `FROM ... AS build`, found %d", builds))
	}
	return errs
}

func copyPinInputs(t *testing.T) string {
	t.Helper()
	root := repoRoot(t)
	dst := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dst, ".github", "workflows"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := []string{"go.mod", "go.sum", "Dockerfile"}
	wfs, _ := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	for _, w := range wfs {
		rel, _ := filepath.Rel(root, w)
		files = append(files, rel)
	}
	for _, f := range files {
		b, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dst, f), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// dockerBuildFROMRe matches the whole `FROM ... AS build` line of the real
// Dockerfile, whatever its current image reference.
var dockerBuildFROMRe = regexp.MustCompile(`(?mi)^FROM\s.*\sAS\s+build\s*$`)

func mutateBuildFROM(t *testing.T, dir, repl string) {
	t.Helper()
	path := filepath.Join(dir, "Dockerfile")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(dockerBuildFROMRe.FindAllIndex(b, -1)) != 1 {
		t.Fatalf("%s: want exactly one FROM ... AS build line; mutation would be vacuous", path)
	}
	out := dockerBuildFROMRe.ReplaceAllLiteralString(string(b), repl)
	if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mutateFile(t *testing.T, path, old, repl string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), old) {
		t.Fatalf("%s: %q not found; mutation would be vacuous", path, old)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(b), old, repl, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestStackPinsRealTreePasses(t *testing.T) {
	if errs := checkStackPins(repoRoot(t)); len(errs) != 0 {
		t.Fatalf("real tree must satisfy ADR-001 pins:\n  %s", strings.Join(errs, "\n  "))
	}
}

func TestStackPinsMutationsFail(t *testing.T) {
	ci := ".github/workflows/ci.yml"
	cases := []struct {
		name  string
		apply func(t *testing.T, dir string)
		want  string
	}{
		{"baseline copy passes", func(t *testing.T, dir string) {}, ""},
		{"go.sum deleted", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "go.sum")); err != nil {
				t.Fatal(err)
			}
		}, "go.sum is missing"},
		{"go.sum emptied", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "go.sum"), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}, "go.sum is missing or empty"},
		{"toolchain changed", func(t *testing.T, dir string) {
			mutateFile(t, filepath.Join(dir, "go.mod"), "toolchain go1.27.4", "toolchain go1.27.3")
		}, "`toolchain` line is go1.27.3"},
		{"toolchain removed", func(t *testing.T, dir string) {
			mutateFile(t, filepath.Join(dir, "go.mod"), "toolchain go1.27.4\n", "")
		}, "`toolchain` line is absent"},
		{"go line changed", func(t *testing.T, dir string) {
			mutateFile(t, filepath.Join(dir, "go.mod"), "\ngo 1.26.0\n", "\ngo 1.25.0\n")
		}, "`go` line is"},
		{"setup-go go-version 1.26 (one step)", func(t *testing.T, dir string) {
			mutateFile(t, filepath.Join(dir, ci), "go-version: ${{ env.GO_VERSION }}", "go-version: '1.26'")
		}, `setup-go go-version "1.26"`},
		{"workflow GO_VERSION env drifted", func(t *testing.T, dir string) {
			mutateFile(t, filepath.Join(dir, ci), `GO_VERSION: "1.27.4"`, `GO_VERSION: "1.26.0"`)
		}, `setup-go go-version "1.26.0"`},
		{"GO_VERSION env removed", func(t *testing.T, dir string) {
			mutateFile(t, filepath.Join(dir, ci), `GO_VERSION: "1.27.4"`, `GO_OTHER: "1.27.4"`)
		}, "is undefined"},
		{"setup-go reads another file", func(t *testing.T, dir string) {
			mutateFile(t, filepath.Join(dir, ci), "go-version: ${{ env.GO_VERSION }}", "go-version-file: .go-version")
		}, `go-version-file ".go-version"`},
		{"setup-go version source removed", func(t *testing.T, dir string) {
			mutateFile(t, filepath.Join(dir, ci), "go-version: ${{ env.GO_VERSION }}", "cache: 'false'")
		}, "exactly one of"},
		{"setup-go stable", func(t *testing.T, dir string) {
			mutateFile(t, filepath.Join(dir, ci), "go-version: ${{ env.GO_VERSION }}", "go-version: stable")
		}, `go-version "stable"`},
		{"setup-go check-latest true", func(t *testing.T, dir string) {
			mutateFile(t, filepath.Join(dir, ci), "check-latest: false", "check-latest: true")
		}, "check-latest"},
		{"echo below ADR floor", func(t *testing.T, dir string) {
			mod := "github.com/labstack/" + "echo/v5" // split: echo-containment greps the path
			mutateFile(t, filepath.Join(dir, "go.mod"), mod+" v5.4.4", mod+" v5.4.3")
		}, "echo/v5 is v5.4.3"},
		{"go-redis off ADR minor", func(t *testing.T, dir string) {
			mutateFile(t, filepath.Join(dir, "go.mod"), "gopkg.in/yaml.v3 v3.0.1", "gopkg.in/yaml.v3 v3.0.1\n\tgithub.com/redis/go-redis/v9 v9.21.0")
		}, "go-redis/v9 is v9.21.0"},
		{"unclassified direct dependency", func(t *testing.T, dir string) {
			mutateFile(t, filepath.Join(dir, "go.mod"), "gopkg.in/yaml.v3 v3.0.1", "gopkg.in/yaml.v3 v3.0.1\n\tgithub.com/example/unpinned v0.1.0")
		}, "no ADR-001 row"},
		{"Dockerfile FROM build line only -> golang:1.26 (verifier F-1)", func(t *testing.T, dir string) {
			mutateBuildFROM(t, dir, "FROM golang:1.26 AS build")
		}, "Dockerfile build stage"},
		{"Dockerfile FROM build line keeps digest, tag 1.26", func(t *testing.T, dir string) {
			mutateBuildFROM(t, dir, "FROM golang:1.26-bookworm@sha256:"+strings.Repeat("a", 64)+" AS build")
		}, "Dockerfile build stage"},
		{"Dockerfile FROM build line digest only, no tag", func(t *testing.T, dir string) {
			mutateBuildFROM(t, dir, "FROM golang@sha256:"+strings.Repeat("a", 64)+" AS build")
		}, "Dockerfile build stage"},
		{"Dockerfile FROM build line tag without digest", func(t *testing.T, dir string) {
			mutateBuildFROM(t, dir, "FROM golang:1.27.4-bookworm AS build")
		}, "Dockerfile build stage"},
		{"Dockerfile build stage removed", func(t *testing.T, dir string) {
			mutateBuildFROM(t, dir, "FROM golang:1.27.4-bookworm@sha256:"+strings.Repeat("a", 64)+" AS builder")
		}, "Dockerfile build stage"},
		{"Dockerfile comment only changes (FROM intact) stays green", func(t *testing.T, dir string) {
			mutateFile(t, filepath.Join(dir, "Dockerfile"), "golang:1.27.4-bookworm,", "golang:1.26.0-bookworm,")
		}, ""},
		{"Dockerfile --platform flag on pinned FROM stays green", func(t *testing.T, dir string) {
			b, _ := os.ReadFile(filepath.Join(dir, "Dockerfile"))
			m := dockerBuildFROMRe.FindString(string(b))
			mutateBuildFROM(t, dir, strings.Replace(m, "FROM ", "FROM --platform=$BUILDPLATFORM ", 1))
		}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := copyPinInputs(t)
			c.apply(t, dir)
			errs := checkStackPins(dir)
			out := strings.Join(errs, "\n")
			t.Logf("findings:\n%s", out)
			if c.want == "" {
				if len(errs) != 0 {
					t.Fatalf("baseline copy must pass:\n%s", out)
				}
				return
			}
			if !strings.Contains(out, c.want) {
				t.Fatalf("want a finding containing %q, got:\n%s", c.want, out)
			}
		})
	}
}
