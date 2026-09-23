package httpapi_test

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// This file is the SECOND layer of the contract-drift lane's protection.
//
// The first layer is scripts/contract-drift-guard.py, a recipe step that runs
// before `go test` and therefore cannot be deselected by it. That matters,
// because the first attempt at this fix put the rule in an ordinary Go test
// inside the lane — and a Go test inside the lane is selected by the same
// `go test` invocation it polices. `-run 'TestVerifier'` deselected the guard
// that forbids `-run`, and the lane printed `ok … [no tests to run]` and exited
// 0 with a vendored contract file edited in place. A juror the defendant can
// dismiss is not a control.
//
// So the tests here do not pretend to be the control. They hold the SHAPE of
// the lane — that both guard steps are still in the recipe — and they exercise
// the shell guard against every bypass known to have worked, so a guard that
// silently stopped refusing one of them is itself a red lane. Removing the
// shell guard from the recipe while also adding `-run` takes two edits to
// /Makefile, which CODEOWNERS assigns to the owner; and `make ci`, `test` and
// `test-noskip` run ./... unfiltered and still catch the drift regardless.

const (
	repoRoot  = "../.."
	guardPath = "./scripts/contract-drift-guard.py"
)

// testSelectingFlags change WHICH tests run. Any of them on the lane can
// silently deselect a guard.
var testSelectingFlags = []string{"-run", "-skip", "-short", "-tags", "-bench", "-fuzz"}

// resolvedLaneCommands asks make what the lane will ACTUALLY run, rather than
// parsing the Makefile text. Asking make resolves variables, includes and
// duplicate-target overrides in one move — each of which defeated the earlier
// text parser.
//
// make is started ONLY through scripts/makegate.py, the digest-gated helper
// every make call in this repository goes through: a `make --dry-run` is not
// read-only (make evaluates the file and remakes an out-of-date makefile while
// reading it), and this runs in the test-noskip lane, where no anchor step
// precedes it (PR #5 security re-review, R-1).
func resolvedLaneCommands(t *testing.T) []string {
	t.Helper()
	cmd := exec.Command("python3", "scripts/makegate.py", "--", "--dry-run", "--no-print-directory", "contract-drift")
	cmd.Dir = repoRoot
	cmd.Env = filteredEnv()
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("`makegate.py -- --dry-run contract-drift` failed: %v\n%s%s", err, out, stderr.String())
	}
	var commands []string
	var pending string
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			pending += strings.TrimSuffix(line, "\\") + " "
			continue
		}
		commands = append(commands, strings.TrimSpace(pending+line))
		pending = ""
	}
	if strings.TrimSpace(pending) != "" {
		commands = append(commands, strings.TrimSpace(pending))
	}
	if len(commands) == 0 {
		t.Fatal("the contract-drift lane resolves to no commands at all")
	}
	return commands
}

func filteredEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		switch {
		case strings.HasPrefix(kv, "MAKEFLAGS="),
			strings.HasPrefix(kv, "MFLAGS="),
			strings.HasPrefix(kv, "MAKELEVEL="):
			continue
		}
		env = append(env, kv)
	}
	return env
}

// TestTheContractDriftLaneIsGuardedFromOutsideGoTest pins the lane's shape: the
// shell guard brackets the test command. If either step is dropped, the only
// remaining protection is the tests in this file — which `-run` can remove.
func TestTheContractDriftLaneIsGuardedFromOutsideGoTest(t *testing.T) {
	commands := resolvedLaneCommands(t)

	first, last := commands[0], commands[len(commands)-1]
	if !strings.HasPrefix(first, guardPath) || !strings.Contains(first, " recipe") {
		t.Errorf("the lane's FIRST command must be `%s recipe`, so the lane's shape is checked\n"+
			"\tbefore any test runs — a check inside `go test` can be deselected by `-run`.\n\tgot: %s",
			guardPath, first)
	}
	if !strings.HasPrefix(last, guardPath) || !strings.Contains(last, " ran") {
		t.Errorf("the lane's LAST command must be `%s ran <report>`, which is the authority on\n"+
			"\twhether the lane passed and refuses a lane that ran zero tests.\n\tgot: %s",
			guardPath, last)
	}

	var tested []string
	for _, c := range commands {
		if !strings.HasPrefix(c, guardPath) {
			tested = append(tested, c)
		}
	}
	if len(tested) != 1 {
		t.Fatalf("the lane must run exactly one `go test`; it runs %d commands besides the guard:\n\t%s",
			len(tested), strings.Join(tested, "\n\t"))
	}
	if !strings.Contains(tested[0], "go test") {
		t.Errorf("the lane's test command does not invoke `go test`: %s", tested[0])
	}
}

// TestTheContractDriftLaneCarriesNoTestSelectingFlag is the second layer of the
// flag rule. The shell guard enforces it first; this fails too, so a reader of
// the test output sees why.
func TestTheContractDriftLaneCarriesNoTestSelectingFlag(t *testing.T) {
	for _, c := range resolvedLaneCommands(t) {
		if strings.HasPrefix(c, guardPath) {
			continue
		}
		for _, tok := range strings.Fields(c) {
			tok = strings.Trim(tok, "'\"")
			for _, flag := range testSelectingFlags {
				if tok == flag || strings.HasPrefix(tok, flag+"=") {
					t.Errorf("the contract-drift lane carries %s.\n"+
						"\tThe lane must select by PACKAGE, not by test name: a name filter silently drops\n"+
						"\ta guard out of the lane the day someone renames it. That is finding F7.\n\tcommand: %s",
						flag, c)
				}
			}
		}
	}
}

// TestTheContractDriftLaneRunsEveryPackageHoldingAVendoredFileGuard is the
// second layer of the coverage rule: a guard written in a package the lane does
// not run is a guard that does not guard this lane.
func TestTheContractDriftLaneRunsEveryPackageHoldingAVendoredFileGuard(t *testing.T) {
	lane := map[string]bool{}
	var listed []string
	for _, c := range resolvedLaneCommands(t) {
		if strings.HasPrefix(c, guardPath) {
			continue
		}
		for _, tok := range strings.Fields(c) {
			if strings.HasPrefix(tok, "./") {
				p := strings.Trim(strings.TrimPrefix(tok, "./"), "/")
				lane[p] = true
				listed = append(listed, p)
			}
		}
	}
	sort.Strings(listed)
	if len(listed) == 0 {
		t.Fatal("the contract-drift lane names no package to test")
	}
	for _, g := range packagesGuardingVendoredFiles(t) {
		if !lane[g] {
			t.Errorf("package %q contains a test that reads a vendored contract file, but the lane\n"+
				"\tdoes not run it, so a mutation of that file survives `make contract-drift`.\n"+
				"\tAdd ./%s/ to the contract-drift recipe.\n\tlane packages: %v", g, g, listed)
		}
	}
}

// vendoredFileMarkers are derived from the manifest, not written down here, so
// adding a third vendored file extends this check automatically.
func vendoredFileMarkers(t *testing.T) []string {
	t.Helper()
	markers := []string{filepath.Base(manifestPath)}
	for _, f := range loadManifest(t).Files {
		markers = append(markers, filepath.Base(f.VendoredPath))
	}
	if len(markers) < 3 {
		t.Fatalf("expected the manifest to pin at least two vendored files, got markers %v", markers)
	}
	return markers
}

func packagesGuardingVendoredFiles(t *testing.T) []string {
	t.Helper()
	markers := vendoredFileMarkers(t)
	seen := map[string]bool{}
	err := filepath.WalkDir(repoRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "bin", "docs", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, m := range markers {
			if strings.Contains(string(raw), m) {
				rel, err := filepath.Rel(repoRoot, filepath.Dir(path))
				if err != nil {
					return err
				}
				seen[filepath.ToSlash(rel)] = true
				return nil
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the module for vendored-file guards: %v", err)
	}
	if len(seen) == 0 {
		t.Fatal("found no test file that reads a vendored file; either the walk is broken or the guards are gone")
	}
	out := make([]string, 0, len(seen))
	for dir := range seen {
		out = append(out, dir)
	}
	sort.Strings(out)
	return out
}

// ------------------------------------------------ the guard's own behaviour --

// laneFixture builds a throwaway repository whose contract-drift lane has the
// same three-step shape as the real one, so the guard can be driven against
// recipes this repository must never contain. The guard locates its root from
// its own path, so copying it into the fixture is what redirects it — there is
// no environment override that could also be used to escape it in the real
// repository.
type laneFixture struct {
	dir string
	t   *testing.T
}

func newLaneFixture(t *testing.T) *laneFixture {
	t.Helper()
	dir := t.TempDir()
	f := &laneFixture{dir: dir, t: t}

	mustMkdir(t, filepath.Join(dir, "scripts"))
	mustMkdir(t, filepath.Join(dir, "api"))
	mustMkdir(t, filepath.Join(dir, "internal", "thing"))

	copyFile(t, filepath.Join(repoRoot, "scripts", "contract-drift-guard.py"),
		filepath.Join(dir, "scripts", "contract-drift-guard.py"), 0o755)
	// The guard starts make only through the digest-gated helper, and the
	// helper runs make only on pinned bytes: every fixture Makefile is pinned
	// below, as a reviewer would pin it, so each case tests the GUARD's own
	// refusal rather than the gate's.
	copyFile(t, filepath.Join(repoRoot, "scripts", "makegate.py"),
		filepath.Join(dir, "scripts", "makegate.py"), 0o755)
	mustMkdir(t, filepath.Join(dir, ".github"))
	copyFile(t, filepath.Join(repoRoot, manifestPath[len("../../"):]),
		filepath.Join(dir, "api", "CONTRACT-SOURCE.json"), 0o644)

	// A test that reads a vendored file, so the coverage check has something to
	// find and the clean recipe is a genuine positive control.
	guardTest := "package thing\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\n" +
		"func TestReadsTheVendoredVectors(t *testing.T) {\n" +
		"\tif _, err := os.ReadFile(\"../../api/search-hmac-testvectors.json\"); err != nil {\n\t\tt.Fatal(err)\n\t}\n}\n"
	writeFile(t, filepath.Join(dir, "internal", "thing", "guard_test.go"), guardTest, 0o644)
	return f
}

func (f *laneFixture) writeMakefile(body string, alsoPinned ...string) {
	f.t.Helper()
	writeFile(f.t, filepath.Join(f.dir, "Makefile"), body, 0o644)
	pin := "makefiles:\n"
	for _, rel := range append([]string{"Makefile"}, alsoPinned...) {
		raw, err := os.ReadFile(filepath.Join(f.dir, rel))
		if err != nil {
			f.t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		pin += "  " + rel + ": " + hex.EncodeToString(sum[:]) + "\n"
	}
	writeFile(f.t, filepath.Join(f.dir, ".github", "pinned-makefiles.yml"), pin, 0o644)
}

// run executes the guard's `recipe` check in the fixture and returns its
// combined output and exit code.
func (f *laneFixture) run(extraEnv ...string) (string, int) {
	f.t.Helper()
	cmd := exec.Command("./scripts/contract-drift-guard.py", "recipe")
	cmd.Dir = f.dir
	cmd.Env = append(filteredEnv(), extraEnv...)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		f.t.Fatalf("running the guard: %v\n%s", err, out)
	}
	return string(out), code
}

const cleanRecipe = `SHELL := /bin/bash
.PHONY: contract-drift
contract-drift:
	./scripts/contract-drift-guard.py recipe
	go test -count=1 -json ./internal/thing/ > r.json || true
	./scripts/contract-drift-guard.py ran r.json
`

// TestTheLaneGuardAcceptsAWellFormedLane is the positive control: without it, a
// guard that refused everything would pass every negative case below.
func TestTheLaneGuardAcceptsAWellFormedLane(t *testing.T) {
	f := newLaneFixture(t)
	f.writeMakefile(cleanRecipe)
	out, code := f.run()
	if code != 0 {
		t.Fatalf("the guard refused a well-formed lane (exit %d):\n%s", code, out)
	}
	if !strings.Contains(out, "no test-selecting flag") {
		t.Errorf("expected the guard to report a clean lane, got:\n%s", out)
	}
}

// TestTheLaneGuardRefusesEveryKnownBypass drives the guard against every recipe
// shape that was demonstrated to slip a vendored-file mutation past the lane.
// Each case names the bypass and the phrase the refusal must contain, so a
// guard that started refusing for a different reason is still a failure.
func TestTheLaneGuardRefusesEveryKnownBypass(t *testing.T) {
	cases := []struct {
		name     string
		makefile string
		env      []string
		want     string
	}{
		{
			name: "a -run regex that selects no guard",
			makefile: strings.Replace(cleanRecipe, "go test -count=1 -json",
				"go test -count=1 -json -run 'TestNothingAtAll'", 1),
			want: "carries -run",
		},
		{
			name: "-skip",
			makefile: strings.Replace(cleanRecipe, "go test -count=1 -json",
				"go test -count=1 -json -skip 'TestEveryVendoredFileMatchesItsManifest'", 1),
			want: "carries -skip",
		},
		{
			name:     "-short",
			makefile: strings.Replace(cleanRecipe, "go test -count=1 -json", "go test -count=1 -json -short", 1),
			want:     "carries -short",
		},
		{
			name:     "-tags",
			makefile: strings.Replace(cleanRecipe, "go test -count=1 -json", "go test -count=1 -json -tags noguards", 1),
			want:     "carries -tags",
		},
		{
			name: "-run hidden behind a make variable",
			makefile: "TESTFLAGS ?= -run=TestNothingAtAll\n" +
				strings.Replace(cleanRecipe, "go test -count=1 -json", "go test -count=1 -json $(TESTFLAGS)", 1),
			want: "carries -run",
		},
		{
			name: "a GOFLAGS prefix on the recipe line",
			makefile: strings.Replace(cleanRecipe, "go test -count=1 -json",
				"GOFLAGS=-run=TestNothingAtAll go test -count=1 -json", 1),
			want: "environment assignment",
		},
		{
			name:     "GOFLAGS in the environment",
			makefile: cleanRecipe,
			env:      []string{"GOFLAGS=-run=TestNothingAtAll"},
			want:     "GOFLAGS in the environment",
		},
		{
			// A duplicate that KEEPS the guard line, so the guard still runs.
			// The text scan catches it first, before make's own warning — which
			// matters because that warning's wording is version-dependent.
			name: "a duplicate contract-drift target that keeps the guard",
			makefile: cleanRecipe + "\ncontract-drift:\n\t./scripts/contract-drift-guard.py recipe\n" +
				"\tgo test -count=1 -json -run 'TestNothingAtAll' ./internal/thing/ > r.json || true\n" +
				"\t./scripts/contract-drift-guard.py ran r.json\n",
			want: "declares the `contract-drift` target 2 times",
		},
		{
			name: "go test moved behind a wrapper script",
			makefile: strings.Replace(cleanRecipe, "go test -count=1 -json ./internal/thing/ > r.json || true",
				"./scripts/drift-wrapper.sh > r.json || true", 1),
			want: "instead of `go test`",
		},
		{
			name: "the recipe guard step removed",
			makefile: strings.Replace(cleanRecipe,
				"\t./scripts/contract-drift-guard.py recipe\n", "", 1),
			want: "FIRST command",
		},
		{
			name: "the ran step removed",
			makefile: strings.Replace(cleanRecipe,
				"\t./scripts/contract-drift-guard.py ran r.json\n", "", 1),
			want: "LAST command",
		},
		{
			name:     "a package holding a vendored-file guard dropped from the list",
			makefile: strings.Replace(cleanRecipe, "./internal/thing/", "./scripts/", 1),
			want:     "does not run it",
		},
		// The cases below each disarm the lane in ONE edit, and each is
		// invisible to `make --dry-run` or survives a prefix match. They are
		// why the guard reads the Makefile TEXT as well as asking make.
		{
			name: "a `-` prefix on the recipe guard step",
			makefile: strings.Replace(cleanRecipe,
				"\t./scripts/contract-drift-guard.py recipe",
				"\t-./scripts/contract-drift-guard.py recipe", 1),
			want: "begins with `-`",
		},
		{
			name: "a `-` prefix on the ran step",
			makefile: strings.Replace(cleanRecipe,
				"\t./scripts/contract-drift-guard.py ran r.json",
				"\t-./scripts/contract-drift-guard.py ran r.json", 1),
			want: "begins with `-`",
		},
		{
			name: "`|| true` appended to the recipe guard step",
			makefile: strings.Replace(cleanRecipe,
				"./scripts/contract-drift-guard.py recipe\n",
				"./scripts/contract-drift-guard.py recipe || true\n", 1),
			want: "discards the guard's exit status",
		},
		{
			name: "`|| true` appended to the ran step",
			makefile: strings.Replace(cleanRecipe,
				"./scripts/contract-drift-guard.py ran r.json",
				"./scripts/contract-drift-guard.py ran r.json || true", 1),
			want: "discards the guard's exit status",
		},
		{
			// The natural form of the duplicate-target bypass: the second
			// definition REPLACES the recipe, guard steps included, so no
			// in-recipe check can run to object. The text scan sees it anyway.
			name: "a duplicate target that REPLACES the recipe without the guard",
			makefile: cleanRecipe + "\ncontract-drift:\n" +
				"\tgo test -count=1 -json -run 'TestNothingAtAll' ./internal/thing/ > r.json || true\n",
			want: "declares the `contract-drift` target 2 times",
		},
		{
			name:     "the lane defined inside a make conditional",
			makefile: "ifeq ($(SKIP),1)\n" + cleanRecipe + "endif\n",
			want:     "inside a make conditional",
		},
		{
			name: "the guard step replaced by something that is not the guard",
			makefile: strings.Replace(cleanRecipe,
				"./scripts/contract-drift-guard.py recipe\n", "true\n", 1),
			want: "FIRST command",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newLaneFixture(t)
			f.writeMakefile(tc.makefile)
			out, code := f.run(tc.env...)
			if code == 0 {
				t.Fatalf("the guard ACCEPTED a lane that %s — this bypass is open again:\n%s", tc.name, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("the guard refused the lane, but not for the expected reason.\n"+
					"\twant the message to contain: %q\n\tgot:\n%s", tc.want, out)
			}
		})
	}
}

// TestThisRepositoryPassesItsOwnLaneGuard runs the guard against the REAL
// Makefile from inside the ordinary test suite.
//
// It is what makes the one-edit Makefile mutations red in a lane that cannot be
// removed by editing the Makefile: `test` and `test-noskip` run `./...`, so a
// `-` prefix, a swallowed exit status, or a duplicate target that replaces the
// recipe fails here even when it has removed the in-recipe guard step.
func TestThisRepositoryPassesItsOwnLaneGuard(t *testing.T) {
	cmd := exec.Command("./scripts/contract-drift-guard.py", "recipe")
	cmd.Dir = repoRoot
	cmd.Env = filteredEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("this repository's own contract-drift lane is refused by its guard: %v\n%s", err, out)
	}
}

// TestTheLaneGuardIsAnchoredInTheWorkflow holds the out-of-make anchor. Every
// check inside `make contract-drift` is invoked by a line in the recipe it
// guards, so one Makefile edit can remove the check along with the lane. The
// workflow step cannot be removed that way.
func TestTheLaneGuardIsAnchoredInTheWorkflow(t *testing.T) {
	cmd := exec.Command("./scripts/contract-drift-guard.py", "workflow")
	cmd.Dir = repoRoot
	cmd.Env = filteredEnv()
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the contract-drift lane has lost its out-of-make workflow anchor: %v\n%s", err, out)
	}
}

// An included makefile would be resolved by make, so a variable defined there
// would be expanded before this guard ever saw the recipe. This is its own case
// because it needs a second file. Since the PR #5 closing slice's fix round 2,
// the Makefile grammar (scripts/makegate.py grammar_problems) refuses `include`
// outright, so the lane is refused before make reads either file: the refusal
// names the include, and make is never started. (A -run carried by a variable
// in the Makefile itself is still a "carries -run" row in
// TestTheLaneGuardRefusesEveryKnownBypass.)
func TestTheLaneGuardRefusesAFlagFromAnIncludedMakefile(t *testing.T) {
	f := newLaneFixture(t)
	writeFile(t, filepath.Join(f.dir, "drift.mk"), "TESTFLAGS := -run=TestNothingAtAll\n", 0o644)
	f.writeMakefile("include drift.mk\n"+
		strings.Replace(cleanRecipe, "go test -count=1 -json", "go test -count=1 -json $(TESTFLAGS)", 1), "drift.mk")
	out, code := f.run()
	if code == 0 {
		t.Fatalf("the guard ACCEPTED a lane whose -run came from an included makefile:\n%s", out)
	}
	if !strings.Contains(out, "the `include` directive") || !strings.Contains(out, "make was NOT invoked") {
		t.Errorf("expected the include refused by the Makefile grammar before make, got:\n%s", out)
	}
}

func mustMkdir(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func writeFile(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

func copyFile(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	raw, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("reading %s: %v", src, err)
	}
	writeFile(t, dst, string(raw), mode)
}
