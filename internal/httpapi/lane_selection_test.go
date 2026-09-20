package httpapi_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// This file holds one property: the `contract-drift` lane in the Makefile
// actually runs every test that guards a vendored file.
//
// Why it exists. The lane used to select tests with a `-run` regex of name
// fragments. A regex over names is not a guard, it is a naming habit with a
// deadline: the day someone renames a test to something the regex does not
// match, the test stops running in that lane and nothing says so. That is not
// hypothetical here. The manifest guard was `TestVendoredContractMatchesItsManifest`,
// which the regex's `Contract` fragment matched; it became
// `TestEveryVendoredFileMatchesItsManifest`, which matches no fragment in the
// regex. From then on, editing a vendored contract file in place, or zeroing a
// sha256 in the manifest, left `make contract-drift` GREEN. The mutation died
// only under the broader `make ci`.
//
// The fix is to delete the name coupling rather than lengthen the regex: the
// lane names PACKAGES and runs all of their tests. This test holds that fix in
// place from the other side, so the lane cannot quietly regain a filter and
// cannot quietly stop covering a package where a guard lives.

const makefilePath = "../../Makefile"

// repoRoot is where the module sits, relative to this package's directory.
const repoRoot = "../.."

// testSelectingFlags are the `go test` flags that change WHICH tests run. Any
// of them in the contract-drift recipe can silently deselect a guard, which is
// the exact failure this test exists to prevent. `-count=1` only changes how
// many times the selected tests run, and caching off is what the lane wants.
var testSelectingFlags = []string{"-run", "-skip", "-short", "-tags", "-bench", "-fuzz"}

// contractDriftRecipe returns the shell line(s) of the contract-drift target,
// with make's line continuations joined.
func contractDriftRecipe(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(makefilePath)
	if err != nil {
		t.Fatalf("reading %s: %v", makefilePath, err)
	}
	lines := strings.Split(string(raw), "\n")
	start := -1
	for i, ln := range lines {
		if strings.HasPrefix(ln, "contract-drift:") {
			start = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s declares no contract-drift target; the lane named in .github/required-checks.txt must exist", makefilePath)
	}
	var recipe []string
	for _, ln := range lines[start:] {
		if !strings.HasPrefix(ln, "\t") {
			break
		}
		recipe = append(recipe, strings.TrimSuffix(strings.TrimSpace(ln), "\\"))
	}
	if len(recipe) == 0 {
		t.Fatalf("the contract-drift target in %s has an empty recipe, so the lane runs nothing", makefilePath)
	}
	return strings.Join(recipe, " ")
}

// vendoredFileMarkers are the basenames a test must mention to be reading a
// vendored file. They are derived from the manifest rather than written down
// here, so adding a third vendored file to api/CONTRACT-SOURCE.json extends
// this check automatically.
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

// packagesGuardingVendoredFiles walks the module for _test.go files that read a
// vendored file, and returns the module-relative directories they live in.
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
		body := string(raw)
		for _, m := range markers {
			if strings.Contains(body, m) {
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

// lanePackages returns the package directories the contract-drift recipe runs,
// normalised to module-relative slash paths ("internal/httpapi").
func lanePackages(t *testing.T, recipe string) []string {
	t.Helper()
	var pkgs []string
	for _, tok := range strings.Fields(recipe) {
		if !strings.HasPrefix(tok, "./") {
			continue
		}
		pkgs = append(pkgs, strings.Trim(strings.TrimPrefix(tok, "./"), "/"))
	}
	sort.Strings(pkgs)
	return pkgs
}

// TestTheContractDriftLaneSelectsEveryVendoredFileGuard is the guard that
// replaces the lane's old `-run` regex.
//
// It asserts three things about the Makefile recipe:
//
//  1. it runs `go test`;
//  2. it carries no flag that selects which tests run — so every test in the
//     packages it names is in the lane, whatever it is called;
//  3. every package containing a test that reads a vendored file appears in
//     its package list.
//
// (3) is what makes (2) sufficient: a new guard test written anywhere in an
// already-listed package is in the lane the moment it exists, and a guard
// written in a NEW package turns this test red until the lane lists it.
func TestTheContractDriftLaneSelectsEveryVendoredFileGuard(t *testing.T) {
	recipe := contractDriftRecipe(t)

	if !strings.Contains(recipe, "go test") {
		t.Fatalf("the contract-drift recipe does not run `go test`:\n\t%s", recipe)
	}

	// 2. No test-selecting flag. A lane that filters by name is a lane that
	//    can be escaped by renaming a test.
	for _, flag := range testSelectingFlags {
		for _, tok := range strings.Fields(recipe) {
			tok = strings.Trim(tok, "'\"")
			if tok == flag || strings.HasPrefix(tok, flag+"=") {
				t.Errorf("the contract-drift recipe carries %s.\n"+
					"\tThe lane must select by PACKAGE, not by test name or tag: a name filter silently\n"+
					"\tdrops a guard out of the lane the day someone renames it, with nothing to say so.\n"+
					"\tThat is finding F7, and it is why this test exists.\n\trecipe: %s", flag, recipe)
			}
		}
	}

	// 3. Every package holding a vendored-file guard is in the lane.
	lane := lanePackages(t, recipe)
	if len(lane) == 0 {
		t.Fatalf("the contract-drift recipe names no package to test:\n\t%s", recipe)
	}
	inLane := map[string]bool{}
	for _, p := range lane {
		inLane[p] = true
		if _, err := os.Stat(filepath.Join(repoRoot, p)); err != nil {
			t.Errorf("the contract-drift lane names package %q, which does not exist: %v", p, err)
		}
	}

	guards := packagesGuardingVendoredFiles(t)
	for _, g := range guards {
		if !inLane[g] {
			t.Errorf("package %q contains a test that reads a vendored contract file, but the\n"+
				"\tcontract-drift lane does not run it, so a mutation of that file survives `make contract-drift`.\n"+
				"\tAdd ./%s/ to the contract-drift recipe in %s.\n\tlane packages: %v",
				g, g, makefilePath, lane)
		}
	}
	t.Logf("contract-drift runs %v with no test-selecting flag; vendored-file guards live in %v", lane, guards)
}
