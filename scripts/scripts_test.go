package scripts_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// requirePython fails — never skips — when the interpreter or PyYAML is missing:
// a required check that cannot run is BLOCKED, not passed.
func requirePython(t *testing.T) {
	t.Helper()
	out, err := exec.Command("python3", "-c", "import yaml").CombinedOutput()
	if err != nil {
		t.Fatalf("BLOCKED: python3 with PyYAML is required by the CI guards and is not available: %v\n%s", err, out)
	}
}

// stripped are removed from every child environment, so a test run under
// `make test` (which exports MAKEFLAGS and MAKELEVEL) or on a developer's shell
// starts from a clean slate. The Makefile's own `?=` names are included: the
// strict anchor refuses them, and a developer may have one set.
var stripped = map[string]bool{
	"MAKEFLAGS": true, "GNUMAKEFLAGS": true, "MFLAGS": true, "MAKELEVEL": true,
	"MAKE_RESTARTS": true, "MAKEOVERRIDES": true, "MAKECMDGOALS": true, "MAKEFILES": true,
	"BASH_ENV": true, "ENV": true, "GOFLAGS": true,
	"VERSION": true, "COMMIT": true, "BUILD_TIME": true, "IMAGE": true, "CORE": true, "CORE_REMOTE": true,
}

func cleanEnv(extra ...string) []string {
	env := []string{}
	for _, kv := range os.Environ() {
		if !stripped[strings.SplitN(kv, "=", 2)[0]] {
			env = append(env, kv)
		}
	}
	return append(env, extra...)
}

func run(t *testing.T, dir string, env []string, name string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out), code
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// copyTree copies what the CI guards read — .github/, the scripts and their
// fixtures, the Makefile and the Dockerfile — into a fresh temporary
// directory, so a mutation never touches the checkout.
func copyTree(t *testing.T) string {
	t.Helper()
	return copyTreeWith(t)
}

// copyTreeWith is copyTree plus the named extra paths (for a guard that also
// reads the packages or the vendored contract).
func copyTreeWith(t *testing.T, extra ...string) string {
	t.Helper()
	src := repoRoot(t)
	dst := t.TempDir()
	for _, rel := range append([]string{".github", "scripts", "Makefile", "Dockerfile"}, extra...) {
		from := filepath.Join(src, rel)
		err := filepath.WalkDir(from, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			r, _ := filepath.Rel(src, path)
			to := filepath.Join(dst, r)
			if d.IsDir() {
				return os.MkdirAll(to, 0o755)
			}
			if !d.Type().IsRegular() {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			return os.WriteFile(to, b, info.Mode().Perm())
		})
		if err != nil {
			t.Fatalf("copying %s: %v", rel, err)
		}
	}
	return dst
}

// mutation is one controlled edit. `old` must occur EXACTLY once in the file,
// or the harness refuses it: an edit that did not apply proves nothing, and
// one that applied twice proves something else. An empty `old` appends.
type mutation struct {
	name   string
	file   string
	old    string
	new    string
	create map[string]string // extra files written alongside, e.g. an included makefile
	env    []string          // extra environment for the command
	want   string            // lower-cased substring the refusal must contain
}

type applied struct {
	path, before, after string
	original            []byte
}

// apply performs the edit and returns the digests. It REFUSES — returns an
// error — when the edit does not apply exactly once or leaves the bytes
// unchanged.
func apply(dir string, m mutation) (applied, error) {
	path := filepath.Join(dir, m.file)
	orig, err := os.ReadFile(path)
	if err != nil {
		return applied{}, err
	}
	var next string
	if m.old == "" {
		next = string(orig) + m.new
	} else {
		if n := strings.Count(string(orig), m.old); n != 1 {
			return applied{}, fmt.Errorf("mutation %q did not apply: %q occurs %d time(s) in %s, want exactly 1",
				m.name, m.old, n, m.file)
		}
		next = strings.Replace(string(orig), m.old, m.new, 1)
	}
	a := applied{path: path, before: digest(orig), after: digest([]byte(next)), original: orig}
	if a.before == a.after {
		return applied{}, fmt.Errorf("mutation %q changed nothing in %s", m.name, m.file)
	}
	if err := os.WriteFile(path, []byte(next), 0o644); err != nil {
		return applied{}, err
	}
	for rel, body := range m.create {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0o644); err != nil {
			return applied{}, err
		}
	}
	return a, nil
}

func (a applied) restore(t *testing.T, m mutation) {
	t.Helper()
	if err := os.WriteFile(a.path, a.original, 0o644); err != nil {
		t.Fatal(err)
	}
	for rel := range m.create {
		_ = os.Remove(filepath.Join(filepath.Dir(a.path), rel))
	}
	b, err := os.ReadFile(a.path)
	if err != nil {
		t.Fatal(err)
	}
	if got := digest(b); got != a.before {
		t.Fatalf("restore of %s is not byte-identical: %s, want %s", a.path, got, a.before)
	}
}

func firstFail(out string) string {
	for _, line := range strings.Split(out, "\n") {
		l := strings.TrimSpace(line)
		if strings.HasPrefix(l, "FAIL") || strings.HasPrefix(l, "ci-required-guard:") ||
			strings.HasPrefix(l, "REQUIRED-CHECKS") || strings.HasPrefix(l, "::error::") {
			return l
		}
	}
	return "(no FAIL line)"
}

// redThenGreen applies m in a fresh copy, requires `cmd` to go RED naming m.want,
// restores byte-identically, and requires `cmd` to go GREEN again.
func redThenGreen(t *testing.T, m mutation, cmd func(dir string, env []string) (string, int)) {
	t.Helper()
	dir := copyTree(t)
	a, err := apply(dir, m)
	if err != nil {
		t.Fatal(err)
	}
	out, code := cmd(dir, cleanEnv(m.env...))
	if code == 0 {
		t.Fatalf("%s: GREEN (exit 0) after the mutation — the evasion was not refused.\n%s", m.name, out)
	}
	if !strings.Contains(strings.ToLower(out), m.want) {
		t.Fatalf("%s: red (exit %d) but not for the declared reason %q:\n%s", m.name, code, m.want, out)
	}
	a.restore(t, m)
	out2, code2 := cmd(dir, cleanEnv())
	if code2 != 0 {
		t.Fatalf("%s: still red after a byte-identical restore — the red was not the mutation's:\n%s", m.name, out2)
	}
	t.Logf("%s | %s sha256 %s -> %s -> restored %s | RED exit %d: %s | restored: GREEN exit 0",
		m.name, m.file, a.before[:12], a.after[:12], a.before[:12], code, firstFail(out))
}

// ---------------------------------------------------------------------------
// the harness refuses a mutation that did not apply
// ---------------------------------------------------------------------------

func TestTheHarnessRefusesAMutationThatDidNotApply(t *testing.T) {
	dir := copyTree(t)
	for _, m := range []mutation{
		{name: "absent", file: ".github/workflows/ci.yml", old: "run: make no-such-target\n", new: "x"},
		{name: "ambiguous", file: ".github/workflows/ci.yml", old: "runs-on: ubuntu-24.04\n", new: "x"},
		{name: "no-op", file: ".github/workflows/ci.yml", old: "        run: make test\n", new: "        run: make test\n"},
	} {
		if _, err := apply(dir, m); err == nil {
			t.Errorf("the harness accepted mutation %q, which cannot have applied cleanly", m.name)
		} else {
			t.Logf("refused, as required: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// ci-required-guard.py — default-deny on the shape of make and direct steps
// ---------------------------------------------------------------------------

func guardPy(t *testing.T) func(dir string, env []string) (string, int) {
	return func(dir string, env []string) (string, int) {
		return run(t, dir, env, "python3", filepath.Join(dir, "scripts", "ci-required-guard.py"))
	}
}

const (
	ciYML      = ".github/workflows/ci.yml"
	manifest   = ".github/required-checks.txt"
	pinsYML    = ".github/pinned-steps.yml"
	anchorRun  = "        run: ./scripts/make-integrity-guard.sh --workflow\n      - name: make test\n"
	makeTest   = "        run: make test\n"
	testJob    = "  test:\n    name: test\n    runs-on: ubuntu-24.04\n"
	noskipJob  = "  test-noskip:\n    name: test-noskip\n    runs-on: ubuntu-24.04\n"
	goVersion  = "  GO_VERSION: \"1.27.1\"\n"
	directGoTL = "          go test -count=1 -json ./... > unit-events.json || rc=$?\n"
)

// Every one-word workflow-line evasion that defeated vizra-core's blacklist
// (core PR#9 VERIFY § 3b and round two), applied to THIS repository's real
// `make test` step, plus the surroundings the brief names. Each must be red.
func guardEvasions() []mutation {
	return []mutation{
		// --- the make step's bytes (FINDING 1, 3 and friends) ---
		{name: "make -i", file: ciYML, old: makeTest, new: "        run: make -i test\n", want: "not byte-equal"},
		{name: "make -j -i (optarg swallow)", file: ciYML, old: makeTest, new: "        run: make -j -i test\n", want: "not byte-equal"},
		{name: "make -l -i (optarg swallow)", file: ciYML, old: makeTest, new: "        run: make -l -i test\n", want: "not byte-equal"},
		{name: "MAKEFLAGS=-i prefix", file: ciYML, old: makeTest, new: "        run: MAKEFLAGS=-i make test\n", want: "not byte-equal"},
		{name: "export MAKEFLAGS above", file: ciYML, old: makeTest, new: "        run: |\n          export MAKEFLAGS=-i\n          make test\n", want: "not byte-equal"},
		{name: "export GNUMAKEFLAGS above", file: ciYML, old: makeTest, new: "        run: |\n          export GNUMAKEFLAGS=-i\n          make test\n", want: "not byte-equal"},
		{name: "M=make; $M -i", file: ciYML, old: makeTest, new: "        run: M=make; $M -i test\n", want: "not byte-equal"},
		{name: "${MAKE:-make} -i", file: ciYML, old: makeTest, new: "        run: ${MAKE:-make} -i test\n", want: "does not run required invocation"},
		{name: "shell function named make", file: ciYML, old: makeTest, new: "        run: make(){ :; }; make test\n", want: "not byte-equal"},
		{name: "backticks", file: ciYML, old: makeTest, new: "        run: echo `make -i test`\n", want: "not byte-equal"},
		{name: "bash -c", file: ciYML, old: makeTest, new: "        run: bash -c \"make -i test\"\n", want: "not byte-equal"},
		{name: "PATH shadow", file: ciYML, old: makeTest, new: "        run: PATH=/tmp/stub:$PATH make test\n", want: "not byte-equal"},
		{name: "override after target", file: ciYML, old: makeTest, new: "        run: make test SHELL=/usr/bin/true\n", want: "not byte-equal"},
		{name: "long-option abbreviation", file: ciYML, old: makeTest, new: "        run: make --ign test\n", want: "not byte-equal"},
		{name: "make -C", file: ciYML, old: makeTest, new: "        run: make -C internal test\n", want: "not byte-equal"},
		{name: "chained", file: ciYML, old: makeTest, new: "        run: go build ./... && make --keep-going test\n", want: "not byte-equal"},
		{name: "untokenisable", file: ciYML, old: makeTest, new: "        run: make test \"\n", want: "not byte-equal"},
		{name: "make token only in a comment", file: ciYML, old: makeTest, new: makeTest + "      - name: innocent\n        run: \"echo hi # make\"\n", want: "not byte-equal"},
		// --- keys on the make step ---
		{name: "step if: always() && false", file: ciYML, old: makeTest, new: makeTest + "        if: always() && false\n", want: "carries ['if']"},
		{name: "step working-directory", file: ciYML, old: makeTest, new: makeTest + "        working-directory: internal\n", want: "carries ['working-directory']"},
		{name: "step shell {0} || true", file: ciYML, old: makeTest, new: makeTest + "        shell: bash -c '{0} || true'\n", want: "carries ['shell']"},
		{name: "step env MAKEFLAGS", file: ciYML, old: makeTest, new: makeTest + "        env:\n          MAKEFLAGS: -i\n", want: "carries ['env']"},
		{name: "step continue-on-error", file: ciYML, old: makeTest, new: makeTest + "        continue-on-error: true\n", want: "continue-on-error"},
		{name: "step timeout-minutes", file: ciYML, old: makeTest, new: makeTest + "        timeout-minutes: 5\n", want: "carries ['timeout-minutes']"},
		// --- the anchor (core round two, R-1) ---
		{name: "anchor deleted", file: ciYML, old: "      - name: refuse a neutered Makefile or make environment (anchor)\n" + anchorRun, new: "      - name: make test\n", want: "not immediately preceded"},
		{name: "anchor not adjacent", file: ciYML, old: anchorRun, new: "        run: ./scripts/make-integrity-guard.sh --workflow\n      - name: between\n        run: echo MAKEFLAGS=-i >> \"$GITHUB_ENV\"\n      - name: make test\n", want: "not immediately preceded"},
		{name: "anchor without --workflow", file: ciYML, old: anchorRun, new: "        run: ./scripts/make-integrity-guard.sh\n      - name: make test\n", want: "not byte-equal to the pinned anchor"},
		{name: "compound anchor writes GITHUB_ENV", file: ciYML, old: anchorRun, new: "        run: ./scripts/make-integrity-guard.sh --workflow && echo MAKEFLAGS=-i >> \"$GITHUB_ENV\"\n      - name: make test\n", want: "not byte-equal to the pinned anchor"},
		{name: "compound anchor writes GITHUB_PATH", file: ciYML, old: anchorRun, new: "        run: ./scripts/make-integrity-guard.sh --workflow && echo /tmp/stub >> \"$GITHUB_PATH\"\n      - name: make test\n", want: "not byte-equal to the pinned anchor"},
		{name: "compound anchor writes MAKELEVEL", file: ciYML, old: anchorRun, new: "        run: ./scripts/make-integrity-guard.sh --workflow && printf 'MAKELEVEL=1\\nMAKEFLAGS=-ki\\n' >> \"$GITHUB_ENV\"\n      - name: make test\n", want: "not byte-equal to the pinned anchor"},
		{name: "fake no-op anchor", file: ciYML, old: anchorRun, new: "        run: ': make-integrity-guard'\n      - name: make test\n", want: "not byte-equal to the pinned anchor"},
		{name: "real anchor then look-alike", file: ciYML, old: anchorRun, new: "        run: ./scripts/make-integrity-guard.sh --workflow\n      - name: look-alike\n        run: \": make-integrity-guard; echo MAKEFLAGS=-i >> $GITHUB_ENV\"\n      - name: make test\n", want: "names make-integrity-guard"},
		{name: "anchor if:", file: ciYML, old: anchorRun, new: "        run: ./scripts/make-integrity-guard.sh --workflow\n        if: false\n      - name: make test\n", want: "anchor step"},
		{name: "anchor env MAKELEVEL", file: ciYML, old: anchorRun, new: "        run: ./scripts/make-integrity-guard.sh --workflow\n        env:\n          MAKELEVEL: \"1\"\n      - name: make test\n", want: "anchor step"},
		// --- deletion / indirection: the positive half ---
		{name: "make test replaced by true", file: ciYML, old: makeTest, new: "        run: \"true\"\n", want: "does not run required invocation"},
		{name: "an extra unpinned make step", file: ciYML, old: makeTest, new: makeTest + "      - name: refuse a neutered Makefile or make environment (anchor)\n        run: ./scripts/make-integrity-guard.sh --workflow\n      - name: extra\n        run: make ci\n", want: "not byte-equal"},
		// --- job and workflow surroundings ---
		{name: "job env MAKEFLAGS", file: ciYML, old: testJob, new: testJob + "    env:\n      MAKEFLAGS: -i\n", want: "job-level env sets makeflags"},
		{name: "job env MAKELEVEL", file: ciYML, old: testJob, new: testJob + "    env:\n      MAKELEVEL: \"1\"\n", want: "job-level env sets makelevel"},
		{name: "job env MAKE_RESTARTS", file: ciYML, old: testJob, new: testJob + "    env:\n      MAKE_RESTARTS: \"1\"\n", want: "job-level env sets make_restarts"},
		{name: "job env MAKECMDGOALS", file: ciYML, old: testJob, new: testJob + "    env:\n      MAKECMDGOALS: ci\n", want: "job-level env sets makecmdgoals"},
		{name: "job env MAKEFILES", file: ciYML, old: testJob, new: testJob + "    env:\n      MAKEFILES: /tmp/x.mk\n", want: "job-level env sets makefiles"},
		{name: "job env BASH_ENV", file: ciYML, old: testJob, new: testJob + "    env:\n      BASH_ENV: /tmp/fn.sh\n", want: "job-level env sets bash_env"},
		{name: "job env ENV", file: ciYML, old: testJob, new: testJob + "    env:\n      ENV: /tmp/fn.sh\n", want: "job-level env sets env"},
		{name: "job env PATH", file: ciYML, old: testJob, new: testJob + "    env:\n      PATH: /tmp/stub:/usr/bin\n", want: "job-level env sets path"},
		{name: "job env VERSION (Makefile ?=)", file: ciYML, old: testJob, new: testJob + "    env:\n      VERSION: x\n", want: "takes from the environment"},
		{name: "job env CORE (Makefile ?=)", file: ciYML, old: testJob, new: testJob + "    env:\n      CORE: /tmp/evil\n", want: "takes from the environment"},
		{name: "job env GOFLAGS on the direct lane", file: ciYML, old: noskipJob, new: noskipJob + "    env:\n      GOFLAGS: -run=^$\n", want: "job-level env sets goflags"},
		{name: "workflow env MAKEOVERRIDES", file: ciYML, old: goVersion, new: goVersion + "  MAKEOVERRIDES: SHELL=/usr/bin/true\n", want: "workflow-level env sets makeoverrides"},
		{name: "workflow env GNUMAKEFLAGS", file: ciYML, old: goVersion, new: goVersion + "  GNUMAKEFLAGS: -i\n", want: "workflow-level env sets gnumakeflags"},
		{name: "workflow env MFLAGS", file: ciYML, old: goVersion, new: goVersion + "  MFLAGS: -i\n", want: "workflow-level env sets mflags"},
		{name: "workflow defaults.run.shell", file: ciYML, old: "permissions:\n  contents: read\n", new: "permissions:\n  contents: read\n\ndefaults:\n  run:\n    shell: bash -c 'exit 0' {0}\n", want: "defaults.run"},
		{name: "job defaults.run.working-directory", file: ciYML, old: testJob, new: testJob + "    defaults:\n      run:\n        working-directory: internal\n", want: "defaults.run"},
		{name: "job container", file: ciYML, old: testJob, new: testJob + "    container: ubuntu:24.04\n", want: "container:"},
		{name: "undigested service image", file: ciYML, old: testJob, new: testJob + "    services:\n      pg:\n        image: postgres:18\n", want: "is not digest-pinned"},
		{name: "job if: false", file: ciYML, old: testJob, new: testJob + "    if: ${{ false }}\n", want: "job-level `if:`"},
		{name: "job continue-on-error", file: ciYML, old: testJob, new: testJob + "    continue-on-error: true\n", want: "continue-on-error"},
		{name: "job reusable workflow", file: ciYML, old: testJob, new: testJob + "    uses: ./.github/workflows/other.yml\n", want: "reusable-workflow"},
		{name: "duplicate run key", file: ciYML, old: makeTest, new: "        run: make -i test\n" + makeTest, want: "duplicate key 'run'"},
		{name: "merge key", file: ciYML, old: "      - name: make test\n" + makeTest, new: "      - <<: {if: \"false\"}\n        name: make test\n" + makeTest, want: "merge key"},
		{name: "runner changed", file: ciYML, old: testJob, new: "  test:\n    name: test\n    runs-on: ubuntu-latest\n", want: "runner other than"},
		{name: "action unpinned", file: ciYML, old: "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0\n        with:\n          go-version: ${{ env.GO_VERSION }}\n          check-latest: false\n      # The anchor: byte-equal to .github/pinned-steps.yml `anchor_step`, and\n      # IMMEDIATELY before the make step (scripts/ci-required-guard.py).\n      - name: refuse a neutered Makefile or make environment (anchor)\n" + anchorRun, new: "      - uses: actions/checkout@v7\n      - uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0\n        with:\n          go-version: ${{ env.GO_VERSION }}\n          check-latest: false\n      # The anchor: byte-equal to .github/pinned-steps.yml `anchor_step`, and\n      # IMMEDIATELY before the make step (scripts/ci-required-guard.py).\n      - name: refuse a neutered Makefile or make environment (anchor)\n" + anchorRun, want: "not pinned to a 40-character"},
		{name: "not on pull_request", file: ciYML, old: "on:\n  pull_request:\n  merge_group:\n", new: "on:\n  merge_group:\n", want: "pull_request"},
		// --- the direct test step (FINDING 6, the swallowed exit) ---
		{name: "direct: report line removed", file: ciYML, old: "          python3 scripts/go-test-report.py \\\n            --events unit-events.json --suite unit \\\n            --floors scripts/test-floors.json --go-exit-file unit-exit.txt || exit 1\n", new: "", want: "not byte-equal to any entry in .github/pinned-steps.yml direct_test_steps"},
		{name: "direct: || exit 1 removed", file: ciYML, old: "--go-exit-file unit-exit.txt || exit 1\n          exit", new: "--go-exit-file unit-exit.txt\n          exit", want: "direct_test_steps"},
		{name: "direct: exit $rc removed", file: ciYML, old: "            --floors scripts/test-floors.json --go-exit-file unit-exit.txt || exit 1\n          exit \"$rc\"\n", new: "            --floors scripts/test-floors.json --go-exit-file unit-exit.txt || exit 1\n", want: "direct_test_steps"},
		{name: "direct: go test exit swallowed", file: ciYML, old: directGoTL, new: "          go test -count=1 -json ./... > unit-events.json || true\n", want: "direct_test_steps"},
		{name: "direct: -run added", file: ciYML, old: directGoTL, new: "          go test -count=1 -run TestX -json ./... > unit-events.json || rc=$?\n", want: "direct_test_steps"},
		{name: "direct: GOFLAGS guard removed", file: ciYML, old: "          if [ -n \"${GOFLAGS+set}\" ]; then\n            echo \"::error::GOFLAGS is set in this step's environment; the go command reads it as extra flags. Refused, not passed.\"\n            exit 1\n          fi\n", new: "", want: "direct_test_steps"},
		{name: "direct: step if:", file: ciYML, old: "      - name: nothing is skipped and every package meets its floor (Q-001), without a make step\n", new: "      - name: nothing is skipped and every package meets its floor (Q-001), without a make step\n        if: github.event_name == 'push'\n", want: "direct test step"},
		// --- the manifest, the floor, the pins, and their agreement (item 4) ---
		{name: "floor lane removed from manifest", file: manifest, old: "\nvendor-contract-selftest\n", new: "\n", want: "'vendor-contract-selftest' is missing"},
		{name: "floor lane commented out", file: manifest, old: "\ntest-noskip\n", new: "\n# test-noskip\n", want: "commented out"},
		{name: "manifest names no job", file: manifest, old: "\ndocker-build\n", new: "\ndocker-build\nno-such-lane\n", want: "matches no job"},
		{name: "required job removed from the workflow", file: ciYML, old: "  vendor-contract-selftest:\n    name: vendor-contract-selftest\n", new: "  vendor-contract-selftest-renamed:\n    name: vendor-contract-selftest-renamed\n", want: "'vendor-contract-selftest' matches no job"},
		{name: "lane dropped from make ci", file: "Makefile", old: " tidy-check vendor-contract-selftest ## Every required lane", new: " tidy-check ## Every required lane", want: "`ci:` and the required lanes disagree"},
		{name: "pins: unknown key", file: pinsYML, old: "", new: "\nextra_allowance: []\n", want: "unknown key"},
		{name: "pins: a body nothing requires", file: pinsYML, old: "  - |\n    make vendor-contract-selftest\n", new: "  - |\n    make vendor-contract-selftest\n  - |\n    make ci\n", want: "that no job is required to run"},
		{name: "Makefile edited, pin not updated", file: "Makefile", old: "SHELL := /bin/bash\n", new: "SHELL := /bin/bash \n", want: "does not match its pin"},
		{name: "makefile pin emptied", file: ".github/pinned-makefiles.yml", old: "\n  Makefile: ", new: "\n#  Makefile: ", want: "must be a single `makefiles:` mapping"},
		{name: "makefile pin: Makefile not covered", file: ".github/pinned-makefiles.yml", old: "\n  Makefile: ", new: "\n  Other: ", want: "does not pin `makefile`"},
		{name: "makefile pin: not a sha256", file: ".github/pinned-makefiles.yml", old: "\n  Makefile: ", new: "\n  Makefile: x", want: "not a `  <path>: <64 lowercase hex sha256>` entry"},
		{name: "pins: duplicate key", file: pinsYML, old: "", new: "\nanchor_step: |\n  ./scripts/make-integrity-guard.sh\n", want: "duplicate key 'anchor_step'"},
	}
}

func TestCIRequiredGuardRefusesEveryEvasion(t *testing.T) {
	requirePython(t)
	for _, m := range guardEvasions() {
		m := m
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			redThenGreen(t, m, guardPy(t))
		})
	}
}

// The guard must pass on this repository's own tree, and must REPORT on what
// it checked — a check that silently stopped running prints nothing at all.
func TestCIRequiredGuardPassesOnTheRealWorkflows(t *testing.T) {
	requirePython(t)
	root := repoRoot(t)
	out, code := run(t, root, cleanEnv(), "python3", filepath.Join(root, "scripts", "ci-required-guard.py"))
	if code != 0 {
		t.Fatalf("the guard fails on the repository's own workflows:\n%s", out)
	}
	for _, want := range []string{
		"all 6 floor lane(s) are present in the manifest",
		"checked lane 'test': 1 make step(s) and 0 direct test step(s) are byte-equal to a pinned body",
		"checked lane 'test-noskip': 0 make step(s) and 1 direct test step(s) are byte-equal to a pinned body",
		"checked lane 'vendor-contract-selftest' runs all 1 required invocation(s)",
		"the suite runs directly, with no make step, from a pinned body in lane(s) ['test-noskip']",
		"`make ci` runs exactly the required make lanes plus test-noskip",
		"every third-party action is pinned to a commit SHA",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the guard did not report %q against the real workflows:\n%s", want, out)
		}
	}
}

// ---------------------------------------------------------------------------
// ci-required-guard.sh — item 3: an emptied manifest fails LOUDLY, by name
// ---------------------------------------------------------------------------

const commentOnlyManifest = "# every lane was commented out\n# build\n# test\n\n"

func TestTheShellGuardFailsLoudlyOnAnEmptiedManifest(t *testing.T) {
	requirePython(t)
	dir := copyTree(t)
	if err := os.WriteFile(filepath.Join(dir, manifest), []byte(commentOnlyManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	out, code := run(t, dir, cleanEnv(), "bash", filepath.Join(dir, "scripts", "ci-required-guard.sh"))
	if code == 0 {
		t.Fatalf("a comment-only manifest passed the guard:\n%s", out)
	}
	if !strings.Contains(out, "REQUIRED-CHECKS MANIFEST EMPTY") {
		t.Fatalf("a comment-only manifest failed the guard (exit %d) WITHOUT saying why — the silent death "+
			"this test exists to prevent:\n%q", code, out)
	}
	t.Logf("comment-only manifest: exit %d, %s", code, firstFail(out))

	// Measured, not assumed: the pre-fix line dies with NO output at all. This
	// pins the reason the fix exists, so a later "simplification" back to it is
	// recognisable.
	sh := filepath.Join(dir, "scripts", "ci-required-guard.sh")
	b, err := os.ReadFile(sh)
	if err != nil {
		t.Fatal(err)
	}
	fixed := `required="$(grep -vE '^\s*(#|$)' "$manifest" | tr -d '\r' || true)"`
	old := `required="$(grep -vE '^\s*(#|$)' "$manifest" | tr -d '\r')"`
	if strings.Count(string(b), fixed) != 1 {
		t.Fatalf("the fixed manifest read is not in ci-required-guard.sh exactly once")
	}
	if err := os.WriteFile(sh, []byte(strings.Replace(string(b), fixed, old, 1)), 0o755); err != nil {
		t.Fatal(err)
	}
	out, code = run(t, dir, cleanEnv(), "bash", sh)
	if code != 1 || strings.TrimSpace(out) != "" {
		t.Fatalf("expected the pre-fix line to die silently with exit 1; got exit %d and %q", code, out)
	}
	t.Logf("pre-fix line, same manifest: exit %d, output %q (silent)", code, out)
}

func TestTheShellGuardPassesOnTheRealTree(t *testing.T) {
	requirePython(t)
	root := repoRoot(t)
	out, code := run(t, root, cleanEnv(), "bash", filepath.Join(root, "scripts", "ci-required-guard.sh"))
	if code != 0 {
		t.Fatalf("ci-required-guard.sh fails on the real tree:\n%s", out)
	}
	if !strings.Contains(out, "ci-required-guard.py: passed") {
		t.Fatalf("ci-required-guard.sh did not reach the default-deny checks:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// make-integrity-guard — the anchor, outside make
// ---------------------------------------------------------------------------

func anchor(t *testing.T, args ...string) func(dir string, env []string) (string, int) {
	return func(dir string, env []string) (string, int) {
		return run(t, dir, env, "python3", append([]string{filepath.Join(dir, "scripts", "make-integrity-guard.py"),
			"--root", dir, "--workflow"}, args...)...)
	}
}

// repin rewrites the copy's .github/pinned-makefiles.yml to the Makefile's
// current digest — what a reviewer does when approving a Makefile edit.
func repin(t *testing.T, dir string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	pin := filepath.Join(dir, ".github", "pinned-makefiles.yml")
	old, err := os.ReadFile(pin)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(old), "\n")
	n := 0
	for i, l := range lines {
		if strings.HasPrefix(l, "  Makefile: ") {
			lines[i] = "  Makefile: " + digest(b)
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the pin file has %d Makefile lines, want 1", n)
	}
	if err := os.WriteFile(pin, []byte(strings.Join(lines, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
}

// THE CONTROL: make runs only on the pinned, reviewed bytes. Any byte change
// to the Makefile without a reviewed pin update is refused BEFORE make is
// invoked — which is why the runner's env file stays empty even for the line
// that first showed the anchor's own `make -pn` writing it. The two constructs
// the vizra-security desk review found past the retired text scanner
// (`.SECONDEXPANSION`, `.RECIPEPREFIX`) are here as plain directive lines: red
// because the bytes changed, whatever make would do with them.
func TestTheAnchorRunsMakeOnlyOnPinnedBytes(t *testing.T) {
	requirePython(t)
	const flagsPin = ".SHELLFLAGS := -eu -o pipefail -c\n"
	cases := []mutation{
		{name: "one byte changed", file: "Makefile", old: "SHELL := /bin/bash\n", new: "SHELL := /bin/bash \n", want: "does not match its pin"},
		{name: "a comment added", file: "Makefile", old: "", new: "# harmless\n", want: "does not match its pin"},
		{name: ".SECONDEXPANSION line (desk review FINDING 1)", file: "Makefile", old: flagsPin, new: flagsPin + ".SECONDEXPANSION:\n", want: "does not match its pin"},
		{name: ".RECIPEPREFIX line (desk review FINDING 2)", file: "Makefile", old: "", new: ".RECIPEPREFIX := >\n", want: "does not match its pin"},
		{name: "an include line", file: "Makefile", old: flagsPin, new: flagsPin + "include inc.mk\n", create: map[string]string{"inc.mk": "X := 1\n"}, want: "does not match its pin"},
		{name: "the line that wrote the env file during the anchor", file: "Makefile", old: flagsPin, new: flagsPin + "POISON := $(shell echo MAKEFLAGS=-i >> \"$$GITHUB_ENV\")\n", want: "does not match its pin"},
		{name: "the pin itself edited", file: ".github/pinned-makefiles.yml", old: "\n  Makefile: ", new: "\n  Makefile: 0", want: "not a `  <path>: <64 lowercase hex sha256>` entry"},
		{name: "the pin no longer covers Makefile", file: ".github/pinned-makefiles.yml", old: "\n  Makefile: ", new: "\n  Other: ", want: "does not pin `makefile`"},
	}
	for _, m := range cases {
		m := m
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			dir := copyTree(t)
			envFile := filepath.Join(dir, "runner-env-file")
			if err := os.WriteFile(envFile, nil, 0o644); err != nil {
				t.Fatal(err)
			}
			a, err := apply(dir, m)
			if err != nil {
				t.Fatal(err)
			}
			out, code := anchor(t)(dir, cleanEnv("GITHUB_ENV="+envFile))
			written, _ := os.ReadFile(envFile)
			if code == 0 || !strings.Contains(strings.ToLower(out), strings.ToLower(m.want)) {
				t.Fatalf("%s: exit %d, want a refusal naming %q:\n%s", m.name, code, m.want, out)
			}
			if !strings.Contains(out, "make was NOT invoked") {
				t.Fatalf("%s: refused, but only after make ran:\n%s", m.name, out)
			}
			if len(written) != 0 {
				t.Fatalf("%s: the runner's env file was written: %q", m.name, written)
			}
			a.restore(t, m)
			out2, code2 := anchor(t)(dir, cleanEnv("GITHUB_ENV="+envFile))
			if code2 != 0 {
				t.Fatalf("%s: still red after a byte-identical restore:\n%s", m.name, out2)
			}
			t.Logf("%s | %s sha256 %s -> %s -> restored %s | RED exit %d, make NOT invoked, env file empty: %s | restored: GREEN",
				m.name, m.file, a.before[:12], a.after[:12], a.before[:12], code, firstFail(out))
		})
	}

	// An unpinned GNUmakefile beside the Makefile: make would read it INSTEAD.
	t.Run("an unpinned GNUmakefile", func(t *testing.T) {
		t.Parallel()
		dir := copyTree(t)
		gm := filepath.Join(dir, "GNUmakefile")
		if err := os.WriteFile(gm, []byte("ci:\n\t@true\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		out, code := anchor(t)(dir, cleanEnv())
		if code == 0 || !strings.Contains(out, "GNUmakefile exists") || !strings.Contains(out, "make was NOT invoked") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
		if err := os.Remove(gm); err != nil {
			t.Fatal(err)
		}
		if _, code2 := anchor(t)(dir, cleanEnv()); code2 != 0 {
			t.Fatal("still red after removing GNUmakefile")
		}
		t.Logf("an unpinned GNUmakefile | RED exit %d, make NOT invoked: %s | removed: GREEN", code, firstFail(out))
	})

	// An included file that is NOT pinned, with the Makefile re-pinned as if the
	// include line had been reviewed: the static read set of the reviewed bytes
	// names inc.mk, which has no pin, so make is never started.
	t.Run("an extra included file, Makefile re-pinned", func(t *testing.T) {
		t.Parallel()
		m := mutation{name: "include", file: "Makefile", old: flagsPin, new: flagsPin + "include inc.mk\n", create: map[string]string{"inc.mk": "X := 1\n"}}
		dir := copyTree(t)
		pinBefore, _ := os.ReadFile(filepath.Join(dir, ".github", "pinned-makefiles.yml"))
		a, err := apply(dir, m)
		if err != nil {
			t.Fatal(err)
		}
		repin(t, dir)
		out, code := anchor(t)(dir, cleanEnv())
		if code == 0 || !strings.Contains(out, "make would read inc.mk, which has no entry") || !strings.Contains(out, "make was NOT invoked") {
			t.Fatalf("exit %d:\n%s", code, out)
		}
		a.restore(t, m)
		if err := os.WriteFile(filepath.Join(dir, ".github", "pinned-makefiles.yml"), pinBefore, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, code2 := anchor(t)(dir, cleanEnv()); code2 != 0 {
			t.Fatal("still red after restoring the Makefile and the pin")
		}
		t.Logf("extra included file, Makefile re-pinned | Makefile sha256 %s -> %s | RED exit %d: %s | restored: GREEN",
			a.before[:12], a.after[:12], code, firstFail(out))
	})
}

// THE RESIDUAL, exercised: a reviewer approved a Makefile edit TOGETHER with
// its pin update. The digest then passes, make runs on the approved bytes, and
// the readings that run afterwards still refuse the known no-op shapes by name.
// This is defence in depth for reviewed bytes, not a grammar of make: anything
// else a reviewer approves runs.
func reviewedBytesEvasions() []mutation {
	const shellPin = "SHELL := /bin/bash\n"
	const flagsPin = ".SHELLFLAGS := -eu -o pipefail -c\n"
	const testRecipe = "\tgo test -race -count=1 $(PKG)\n"
	return []mutation{
		{name: "- prefix on the test recipe", file: "Makefile", old: testRecipe, new: "\t-go test -race -count=1 $(PKG)\n", want: "prefixed `-`"},
		{name: "|| true on the test recipe", file: "Makefile", old: testRecipe, new: "\tgo test -race -count=1 $(PKG) || true\n", want: "ending `|| true`"},
		{name: "; true on the test recipe", file: "Makefile", old: testRecipe, new: "\tgo test -race -count=1 $(PKG); true\n", want: "ending `; true`"},
		{name: "the exempt line in another target", file: "Makefile", old: "\tgo vet $(PKG)\n", new: "\tgo vet $(PKG)\n\tgo test -count=1 -json $(DRIFT_PKGS) > $(DRIFT_REPORT) || true\n", want: "ending `|| true`"},
		{name: "duplicate test target", file: "Makefile", old: "", new: "\ntest:\n\t@true\n", want: "defined 2 times"},
		{name: "test target inside a conditional", file: "Makefile", old: "test: ## Full test suite with the race detector\n" + testRecipe, new: "ifndef VIZRA_NEVER_SET\ntest: ## Full test suite with the race detector\n" + testRecipe + "endif\n", want: "conditional"},
		{name: "|| true produced by an expansion", file: "Makefile", old: "test: ## Full test suite with the race detector\n" + testRecipe, new: "INERT_SWALLOW := || true\ntest: ## Full test suite with the race detector\n\tgo test -race -count=1 $(PKG) $(INERT_SWALLOW)\n", want: "expands to a command whose exit status is discarded"},
		{name: "a NEW ?= variable, set in the environment", file: "Makefile", old: flagsPin, new: flagsPin + "GOCMD ?= go\n", env: []string{"GOCMD=true"}, want: "the environment sets gocmd='true'"},
		// PR #5 closing re-verification, FINDING 5 class: make continues a recipe past a conditional
		// directive, so the reading must too; and a rule line whose comment holds `=` must still have
		// its prerequisites followed into the closure. Inert: `-true`.
		{name: "- prefix on a lane reached from a ci line whose comment holds =", file: "Makefile", old: "vendor-contract-selftest ## Every required lane, in order\n", new: "vendor-contract-selftest inert-lane ## lanes=every one\n\ninert-lane:\n\t-true\n", want: "gate target `inert-lane` has a recipe line prefixed `-`"},
	}
}

func TestMakeIntegrityGuardStillRefusesKnownShapesInReviewedBytes(t *testing.T) {
	requirePython(t)
	for _, m := range reviewedBytesEvasions() {
		m := m
		t.Run(m.name, func(t *testing.T) {
			t.Parallel()
			dir := copyTree(t)
			pinPath := filepath.Join(dir, ".github", "pinned-makefiles.yml")
			pinBefore, err := os.ReadFile(pinPath)
			if err != nil {
				t.Fatal(err)
			}
			a, err := apply(dir, m)
			if err != nil {
				t.Fatal(err)
			}
			repin(t, dir)
			out, code := anchor(t)(dir, cleanEnv(m.env...))
			if code == 0 || !strings.Contains(strings.ToLower(out), m.want) {
				t.Fatalf("%s: exit %d, want a refusal naming %q:\n%s", m.name, code, m.want, out)
			}
			if strings.Contains(out, "does not match its pin") || strings.Contains(out, "not a `  <path>") {
				t.Fatalf("%s: the digest gate did not pass on the re-pinned bytes, so this case tests nothing:\n%s", m.name, out)
			}
			a.restore(t, m)
			if err := os.WriteFile(pinPath, pinBefore, 0o644); err != nil {
				t.Fatal(err)
			}
			if out2, code2 := anchor(t)(dir, cleanEnv()); code2 != 0 {
				t.Fatalf("%s: still red after restoring the Makefile and the pin:\n%s", m.name, out2)
			}
			t.Logf("%s | Makefile sha256 %s -> %s (re-pinned, as a reviewer would) | digest ok, RED exit %d: %s | restored: GREEN",
				m.name, a.before[:12], a.after[:12], code, firstFail(out))
		})
	}
}

// The anchor's OWN environment. Strictness is chosen by `--workflow` — the
// pinned invocation — never by the environment: core's round-two anchor chose
// it from MAKELEVEL's presence, and an earlier `$GITHUB_ENV` write of
// MAKELEVEL=1 beside MAKEFLAGS=-ki then passed (core PR#9 R-2).
func TestMakeIntegrityGuardEnvironment(t *testing.T) {
	requirePython(t)
	stub := t.TempDir()
	if err := os.WriteFile(filepath.Join(stub, "make"), []byte("#!/bin/sh\nexec /usr/bin/make \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		workflow bool
		env      []string
		wantFail bool
		want     string
	}{
		{"workflow/control", true, nil, false, ""},
		{"workflow/MAKEFLAGS=-i", true, []string{"MAKEFLAGS=-i"}, true, "must be unset"},
		{"workflow/MAKEFLAGS present but empty", true, []string{"MAKEFLAGS="}, true, "must be unset"},
		{"workflow/GNUMAKEFLAGS=-ki", true, []string{"GNUMAKEFLAGS=-ki"}, true, "gnumakeflags"},
		{"workflow/MFLAGS=-i", true, []string{"MFLAGS=-i"}, true, "mflags"},
		{"workflow/MAKELEVEL=1 MAKEFLAGS=-ki", true, []string{"MAKELEVEL=1", "MAKEFLAGS=-ki"}, true, "makelevel"},
		{"workflow/MAKELEVEL= (empty) MAKEFLAGS=--ign", true, []string{"MAKELEVEL=", "MAKEFLAGS=--ign"}, true, "makelevel=''"},
		{"workflow/MAKELEVEL=1 alone", true, []string{"MAKELEVEL=1"}, true, "makelevel"},
		{"workflow/MAKE_RESTARTS", true, []string{"MAKE_RESTARTS=1"}, true, "make_restarts"},
		{"workflow/MAKEOVERRIDES", true, []string{"MAKEOVERRIDES=SHELL=/usr/bin/true"}, true, "makeoverrides"},
		{"workflow/MAKECMDGOALS", true, []string{"MAKECMDGOALS=ci"}, true, "makecmdgoals"},
		{"workflow/MAKEFILES", true, []string{"MAKEFILES=/tmp/x.mk"}, true, "makefiles"},
		{"workflow/BASH_ENV", true, []string{"BASH_ENV=/tmp/fn.sh"}, true, "bash_env"},
		{"workflow/ENV", true, []string{"ENV=/tmp/fn.sh"}, true, "env='/tmp/fn.sh'"},
		{"workflow/SHELL=/usr/bin/true", true, []string{"SHELL=/usr/bin/true"}, true, "not a usable shell"},
		{"workflow/VERSION (?=)", true, []string{"VERSION=x"}, true, "version='x'"},
		{"workflow/COMMIT (?=)", true, []string{"COMMIT=x"}, true, "commit='x'"},
		{"workflow/BUILD_TIME (?=)", true, []string{"BUILD_TIME=x"}, true, "build_time='x'"},
		{"workflow/IMAGE (?=)", true, []string{"IMAGE=x"}, true, "image='x'"},
		{"workflow/CORE (?=)", true, []string{"CORE=/tmp/x"}, true, "core='/tmp/x'"},
		{"workflow/CORE_REMOTE (?=)", true, []string{"CORE_REMOTE=evil"}, true, "core_remote='evil'"},
		{"workflow/GOFLAGS", true, []string{"GOFLAGS=-run=^$"}, true, "goflags"},
		{"workflow/non-system make first on PATH", true, []string{"PATH=" + stub + ":" + os.Getenv("PATH")}, true, "which is not in"},
		// No flag: local parity, an ALLOWLIST of what make itself exports. Not a control.
		{"local/control", false, nil, false, ""},
		{"local/make -j2 (4.3)", false, []string{"MAKELEVEL=1", "MAKEFLAGS= -j2 --jobserver-auth=3,4", "MFLAGS=-j2 --jobserver-auth=3,4"}, false, ""},
		{"local/make -j2 (3.81)", false, []string{"MAKELEVEL=1", "MAKEFLAGS= --jobserver-fds=3,4 -j", "MFLAGS=- --jobserver-fds=3,4 -j"}, false, ""},
		{"local/MAKEFLAGS=-ki", false, []string{"MAKELEVEL=1", "MAKEFLAGS=-ki"}, true, "['-ki'] is not a flag make itself"},
		{"local/MAKEFLAGS=n", false, []string{"MAKELEVEL=1", "MAKEFLAGS=n"}, true, "['n'] is not a flag make itself"},
	}
	root := repoRoot(t)
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			args := []string{filepath.Join(root, "scripts", "make-integrity-guard.py"), "--targets", "ci"}
			if tc.workflow {
				args = append(args, "--workflow")
			}
			env := cleanEnv(tc.env...)
			if strings.HasPrefix(strings.Join(tc.env, " "), "PATH=") {
				filtered := []string{}
				for _, kv := range env {
					if !strings.HasPrefix(kv, "PATH=") {
						filtered = append(filtered, kv)
					}
				}
				env = append(filtered, tc.env...)
			}
			out, code := run(t, root, env, "python3", args...)
			if (code != 0) != tc.wantFail {
				t.Fatalf("exit %d, want failed=%v\n%s", code, tc.wantFail, out)
			}
			if tc.want != "" && !strings.Contains(strings.ToLower(out), tc.want) {
				t.Fatalf("the refusal does not mention %q:\n%s", tc.want, out)
			}
			if tc.wantFail {
				t.Logf("RED exit %d: %s", code, firstFail(out))
			}
		})
	}
}

func TestMakeIntegrityGuardPassesOnTheRealMakefile(t *testing.T) {
	requirePython(t)
	root := repoRoot(t)
	out, code := run(t, root, cleanEnv(), "python3", filepath.Join(root, "scripts", "make-integrity-guard.py"), "--workflow")
	if code != 0 {
		t.Fatalf("the anchor fails on this repository's own Makefile:\n%s", out)
	}
	for _, want := range []string{
		"[--workflow (strict)]",
		"make runs only on REVIEWED bytes: Makefile sha256",
		"`make -q` (one invocation, every pinned file a goal) says none would be remade",
		"MAKEFILE_LIST is exactly the pinned set: ['Makefile']",
		"resolves SHELL to the approved /bin/bash",
		"none of the 7 variable(s) the makefiles take from the environment is set",
		"gate target `test` is defined exactly once",
		"gate target `test-noskip` is defined exactly once",
		"gate target `vendor-contract-selftest` is defined exactly once",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the anchor did not report %q; a check that silently stopped running prints nothing:\n%s", want, out)
		}
	}
}

// ---------------------------------------------------------------------------
// go-test-report.py — item 2
// ---------------------------------------------------------------------------

type ev struct {
	Action, Package, Test, Output string
}

func events(evs ...ev) string {
	var b strings.Builder
	for _, e := range evs {
		m := map[string]string{"Action": e.Action, "Package": e.Package}
		if e.Test != "" {
			m["Test"] = e.Test
		}
		if e.Output != "" {
			m["Output"] = e.Output
		}
		j, _ := json.Marshal(m)
		b.Write(j)
		b.WriteByte('\n')
	}
	return b.String()
}

const pa, pb = "example.com/m/a", "example.com/m/b"

func passes(pkg string, n int) []ev {
	out := []ev{}
	for i := 0; i < n; i++ {
		out = append(out, ev{Action: "pass", Package: pkg, Test: fmt.Sprintf("Test%d", i)})
	}
	return append(out, ev{Action: "pass", Package: pkg})
}

func floors(minTests int, pkgs map[string]int, extra string) string {
	j, _ := json.Marshal(pkgs)
	return fmt.Sprintf(`{"suites":{"unit":{"min_tests":%d,"min_package_tests":%s%s}}}`, minTests, j, extra)
}

func TestGoTestReport(t *testing.T) {
	requirePython(t)
	good := append(passes(pa, 3), passes(pb, 2)...)
	okFloors := floors(4, map[string]int{pa: 3, pb: 2}, "")
	cases := []struct {
		name     string
		events   string
		exit     string // "" = no exit file
		floors   string
		wantFail bool
		want     string
		counts   bool // the report reached its verdict and must have printed the counts
	}{
		{"good", events(good...), "0", okFloors, false, "0 skips, every package at or above its floor", true},
		{"a skipped test", events(append(good, ev{Action: "skip", Package: pa, Test: "TestSkipped"})...), "0", okFloors, true, "skipped: example.com/m/a.testskipped", true},
		{"a package with no test files", events(append(good, ev{Action: "skip", Package: "example.com/m/c"})...), "0", okFloors, true, "has no test files", true},
		{"one package below its floor", events(append(passes(pa, 3), passes(pb, 1)...)...), "0", okFloors, true, "package example.com/m/b executed 1 test(s); its recorded floor is 2", true},
		{"a package with no floor", events(append(good, passes("example.com/m/new", 1)...)...), "0", okFloors, true, "with no recorded floor", true},
		{"a floor for a package that vanished", events(passes(pa, 3)...), "0", floors(1, map[string]int{pa: 3, pb: 2}, ""), true, "package example.com/m/b executed 0 test(s)", true},
		{"a failed test", events(append(good, ev{Action: "fail", Package: pa, Test: "TestBroken"}, ev{Action: "fail", Package: pa})...), "1", okFloors, true, "failed: example.com/m/a.testbroken", true},
		{"go test failed with nothing in the stream", events(good...), "2", okFloors, true, "exited 2 but no test or package event reports a failure", true},
		{"a truncated stream", events(good...) + "{\"Action\":\"pa", "0", okFloors, true, "not json events", true},
		{"an empty stream", "", "0", okFloors, true, "contains no `go test -json` events", false},
		{"no exit file", events(good...), "", okFloors, true, "--go-exit-file was not given", false},
		{"a skip allowlist", events(good...), "0", floors(4, map[string]int{pa: 3, pb: 2}, `,"allowed_skips":{"TestX":"flaky"}`), true, "no skip allowlist", false},
		{"a vacuous package floor", events(good...), "0", floors(4, map[string]int{pa: 3, pb: 0}, ""), true, "per-package floors below 1", false},
		{"no per-package floors", events(good...), "0", floors(4, map[string]int{}, ""), true, "no per-package floors", false},
		{"below the suite floor", events(good...), "0", floors(9, map[string]int{pa: 3, pb: 2}, ""), true, "only 5 test(s) executed; the recorded floor for 'unit' is 9", true},
	}
	root := repoRoot(t)
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			write := func(name, body string) string {
				p := filepath.Join(dir, name)
				if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
				return p
			}
			args := []string{filepath.Join(root, "scripts", "go-test-report.py"),
				"--events", write("events.json", tc.events), "--suite", "unit",
				"--floors", write("floors.json", tc.floors)}
			if tc.exit != "" {
				args = append(args, "--go-exit-file", write("exit.txt", tc.exit+"\n"))
			}
			out, code := run(t, dir, cleanEnv(), "python3", args...)
			if (code != 0) != tc.wantFail {
				t.Fatalf("exit %d, want failed=%v\n%s", code, tc.wantFail, out)
			}
			if !strings.Contains(strings.ToLower(out), strings.ToLower(tc.want)) {
				t.Fatalf("the report does not say %q:\n%s", tc.want, out)
			}
			if tc.counts && !strings.Contains(out, "tests executed:") {
				t.Fatalf("the report did not print its counts into the log:\n%s", out)
			}
		})
	}
}

// Every package `go list ./...` knows has a floor, and every floor names a
// package that exists. A floor file that has drifted from the module is a
// floor that protects nothing.
func TestTheRepositoryFloorsCoverEveryPackage(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "scripts", "test-floors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Suites map[string]struct {
			MinTests        int            `json:"min_tests"`
			MinPackageTests map[string]int `json:"min_package_tests"`
			AllowedSkips    map[string]any `json:"allowed_skips"`
		} `json:"suites"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	unit, ok := doc.Suites["unit"]
	if !ok || unit.MinTests < 1 {
		t.Fatalf("scripts/test-floors.json has no usable `unit` suite")
	}
	if len(unit.AllowedSkips) != 0 {
		t.Fatalf("scripts/test-floors.json carries allowed_skips %v; this repository has none", unit.AllowedSkips)
	}
	out, code := run(t, root, cleanEnv(), "go", "list", "./...")
	if code != 0 {
		t.Fatalf("go list ./...: exit %d\n%s", code, out)
	}
	pkgs := strings.Fields(out)
	sort.Strings(pkgs)
	for _, p := range pkgs {
		if unit.MinPackageTests[p] < 1 {
			t.Errorf("package %s has no executed-test floor in scripts/test-floors.json", p)
		}
	}
	for p := range unit.MinPackageTests {
		found := false
		for _, q := range pkgs {
			found = found || p == q
		}
		if !found {
			t.Errorf("scripts/test-floors.json has a floor for %s, which `go list ./...` does not know", p)
		}
	}
}

// ---------------------------------------------------------------------------
// the PINNED direct step, executed — it never swallows go test's exit
// ---------------------------------------------------------------------------

func pinnedDirectBody(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), pinsYML))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Direct []string `yaml:"direct_test_steps"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Direct) != 1 {
		t.Fatalf("expected exactly one pinned direct test body, got %d", len(doc.Direct))
	}
	return doc.Direct[0]
}

// A throwaway module with one package, the real report and a floors file, in
// which the pinned body is run exactly as GitHub runs a `run:` step
// (`bash --noprofile --norc -eo pipefail {0}`).
func directModule(t *testing.T, testSrc string) string {
	t.Helper()
	dir := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(dir, "a"), 0o755))
	must(os.MkdirAll(filepath.Join(dir, "scripts"), 0o755))
	must(os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/m\n\ngo 1.26\n"), 0o644))
	must(os.WriteFile(filepath.Join(dir, "a", "a.go"), []byte("package a\n"), 0o644))
	must(os.WriteFile(filepath.Join(dir, "a", "a_test.go"), []byte(testSrc), 0o644))
	report, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "go-test-report.py"))
	must(err)
	must(os.WriteFile(filepath.Join(dir, "scripts", "go-test-report.py"), report, 0o755))
	must(os.WriteFile(filepath.Join(dir, "scripts", "test-floors.json"),
		[]byte(floors(2, map[string]int{"example.com/m/a": 2}, "")), 0o644))
	return dir
}

func runBody(t *testing.T, dir, body string, env ...string) (string, int) {
	t.Helper()
	script := filepath.Join(dir, "step.sh")
	if err := os.WriteFile(script, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return run(t, dir, cleanEnv(append([]string{"GOTOOLCHAIN=local"}, env...)...),
		"bash", "--noprofile", "--norc", "-eo", "pipefail", script)
}

func TestTheDirectStepCannotSwallowGoTestsExit(t *testing.T) {
	requirePython(t)
	body := pinnedDirectBody(t)
	const passing = "package a\nimport \"testing\"\nfunc TestOne(t *testing.T) {}\nfunc TestTwo(t *testing.T) {}\n"
	const failing = "package a\nimport \"testing\"\nfunc TestOne(t *testing.T) {}\nfunc TestTwo(t *testing.T) { t.Fatal(\"planted\") }\n"
	const skipping = "package a\nimport \"testing\"\nfunc TestOne(t *testing.T) {}\nfunc TestTwo(t *testing.T) { t.Skip(\"planted\") }\n"
	reportLines := "python3 scripts/go-test-report.py \\\n  --events unit-events.json --suite unit \\\n  --floors scripts/test-floors.json --go-exit-file unit-exit.txt || exit 1\n"
	if strings.Count(body, reportLines) != 1 || strings.Count(body, "exit \"$rc\"") != 1 {
		t.Fatalf("the pinned direct body no longer has the shape this test mutates:\n%s", body)
	}
	noReport := strings.Replace(body, reportLines, "", 1)
	noExitRC := strings.Replace(body, "exit \"$rc\"", "", 1)
	neither := strings.Replace(noReport, "exit \"$rc\"", "", 1)
	cases := []struct {
		name     string
		src      string
		body     string
		env      []string
		wantExit bool // true = must exit non-zero
		want     string
	}{
		{"pinned body, passing suite", passing, body, nil, false, "go-test-report: ok"},
		{"pinned body, planted t.Fatal", failing, body, nil, true, "FAILED: example.com/m/a.TestTwo"},
		{"pinned body, planted t.Skip", skipping, body, nil, true, "SKIPPED: example.com/m/a.TestTwo"},
		{"pinned body, GOFLAGS=-run=^$", passing, body, []string{"GOFLAGS=-run=^$"}, true, "GOFLAGS is set"},
		{"report line removed, planted t.Fatal", failing, noReport, nil, true, "go test (unit) exited 1"},
		{"exit $rc removed, planted t.Fatal", failing, noExitRC, nil, true, "FAILED: example.com/m/a.TestTwo"},
		// Why BOTH are pinned: with neither, the step swallows the failure. The
		// guard makes that edit red statically ("direct: report line removed",
		// "direct: exit $rc removed"); this row measures what it would cost.
		{"both removed, planted t.Fatal (the swallow the pin prevents)", failing, neither, nil, false, "go test (unit) exited 1"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := directModule(t, tc.src)
			out, code := runBody(t, dir, tc.body, tc.env...)
			if (code != 0) != tc.wantExit {
				t.Fatalf("step exit %d, want non-zero=%v\n%s", code, tc.wantExit, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("step output does not contain %q:\n%s", tc.want, out)
			}
			t.Logf("step exit %d", code)
		})
	}
}

// ---------------------------------------------------------------------------
// round 2: the newer-sibling remake, the single make gate, and R-2/R-3
// ---------------------------------------------------------------------------

// plantNewerSibling writes a file make's built-in or version-control rules can
// turn into the Makefile, with an mtime a day ahead of the Makefile's.
func plantNewerSibling(t *testing.T, dir, rel string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	orig, err := os.ReadFile(filepath.Join(dir, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(orig, []byte("# sibling bytes nobody pinned\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	future := info.ModTime().Add(24 * time.Hour)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}

// PR #5 re-verification FINDING 2: a newer unpinned `Makefile.sh` made the
// anchor's own `make -pn ci` run make's built-in `% : %.sh` and REWRITE the
// Makefile after the digest had passed. The gate now asks `make -q Makefile`
// first — which runs no ordinary recipe — and stops if make would remake it. For every
// sibling make's rules can turn into the Makefile, the Makefile must be
// byte-identical afterwards; where make would remake it, the anchor is red.
// Where make would NOT (measured on GNU Make 3.81: the RCS `,v` forms for an
// existing, older-than-nothing Makefile), the pinned `make` step would not
// either, so green is the correct answer — and the bytes are still checked.
func TestTheAnchorRefusesAPinnedMakefileMakeWouldRemake(t *testing.T) {
	requirePython(t)
	cases := []struct {
		sibling string
		mustRed bool
	}{
		{"Makefile.sh", true}, {"Makefile.c", true}, {"Makefile.o", true}, {"Makefile.y", true},
		{"Makefile.l", true}, {"SCCS/s.Makefile", true}, {"s.Makefile", true},
		{"Makefile,v", false}, {"RCS/Makefile,v", false}, {"RCS/Makefile", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.sibling, func(t *testing.T) {
			t.Parallel()
			dir := copyTree(t)
			before, _ := os.ReadFile(filepath.Join(dir, "Makefile"))
			plantNewerSibling(t, dir, tc.sibling)
			out, code := anchor(t)(dir, cleanEnv())
			after, _ := os.ReadFile(filepath.Join(dir, "Makefile"))
			if digest(after) != digest(before) {
				t.Fatalf("%s: the anchor let make REWRITE the Makefile (%s -> %s):\n%s",
					tc.sibling, digest(before)[:12], digest(after)[:12], out)
			}
			if tc.mustRed && (code == 0 || !strings.Contains(out, "would REMAKE a pinned makefile")) {
				t.Fatalf("%s: exit %d, want the remake refusal:\n%s", tc.sibling, code, out)
			}
			if code == 0 && !strings.Contains(out, "`make -q` (one invocation, every pinned file a goal) says none would be remade") {
				t.Fatalf("%s: green without the remake probe having passed:\n%s", tc.sibling, out)
			}
			if err := os.RemoveAll(filepath.Join(dir, strings.Split(tc.sibling, "/")[0])); err != nil {
				t.Fatal(err)
			}
			if _, code2 := anchor(t)(dir, cleanEnv()); code2 != 0 {
				t.Fatalf("%s: still red after removing the sibling", tc.sibling)
			}
			t.Logf("newer %s | anchor exit %d: %s | Makefile sha256 %s before and after | removed: GREEN",
				tc.sibling, code, firstFail(out), digest(before)[:12])
		})
	}
}

// R-1: the other two places that read the Makefile with make go through the
// same gate: contract-drift-guard.py (which runs BEFORE the anchor in the
// contract-drift job) and makegate.py's CLI (which the lane test uses in the
// test-noskip lane, where no anchor runs).
func TestEveryOtherMakeCallIsGated(t *testing.T) {
	requirePython(t)
	callers := map[string][]string{
		"contract-drift-guard.py recipe": {"python3", "scripts/contract-drift-guard.py", "recipe"},
		"makegate.py -- --dry-run":       {"python3", "scripts/makegate.py", "--", "--dry-run", "--no-print-directory", "contract-drift"},
	}
	for name, argv := range callers {
		name, argv := name, argv
		for _, variant := range []string{"one byte changed", "newer Makefile.sh", "unpinned GNUmakefile", "MAKEFILES set"} {
			variant := variant
			t.Run(name+"/"+variant, func(t *testing.T) {
				t.Parallel()
				dir := copyTree(t)
				before, _ := os.ReadFile(filepath.Join(dir, "Makefile"))
				env := cleanEnv()
				switch variant {
				case "one byte changed":
					if err := os.WriteFile(filepath.Join(dir, "Makefile"), append(append([]byte{}, before...), ' '), 0o644); err != nil {
						t.Fatal(err)
					}
				case "newer Makefile.sh":
					plantNewerSibling(t, dir, "Makefile.sh")
				case "unpinned GNUmakefile":
					if err := os.WriteFile(filepath.Join(dir, "GNUmakefile"), []byte("contract-drift:\n\t@true\n"), 0o644); err != nil {
						t.Fatal(err)
					}
				case "MAKEFILES set":
					env = append(env, "MAKEFILES=/dev/null")
				}
				out, code := run(t, dir, env, argv[0], argv[1:]...)
				if code == 0 {
					t.Fatalf("%s ran make on %s:\n%s", name, variant, out)
				}
				if !strings.Contains(out, "make was NOT invoked") && !strings.Contains(out, "only `make -q` ran") {
					t.Fatalf("%s refused, but not by the gate before make:\n%s", name, out)
				}
				if variant == "newer Makefile.sh" {
					after, _ := os.ReadFile(filepath.Join(dir, "Makefile"))
					if digest(after) != digest(before) {
						t.Fatalf("%s: make rewrote the Makefile", name)
					}
				}
				t.Logf("%s / %s | exit %d, make not run past the gate", name, variant, code)
			})
		}
	}
}

// R-2: a failed pre-make check stops the anchor BEFORE make, in both modes.
func TestTheAnchorStartsNoMakeAfterAFailedPreMakeCheck(t *testing.T) {
	requirePython(t)
	stub := t.TempDir()
	if err := os.WriteFile(filepath.Join(stub, "make"), []byte("#!/bin/sh\nexec /usr/bin/make \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	root := repoRoot(t)
	for _, tc := range []struct {
		name     string
		workflow bool
		env      []string
	}{
		{"MAKEFILES, --workflow", true, []string{"MAKEFILES=/dev/null"}},
		{"MAKEFILES, local", false, []string{"MAKEFILES=/dev/null"}},
		{"a non-system make first on PATH, --workflow", true, []string{"PATH=" + stub + ":" + os.Getenv("PATH")}},
		{"a non-system make first on PATH, local", false, []string{"PATH=" + stub + ":" + os.Getenv("PATH")}},
		{"MAKEFLAGS=-i, --workflow", true, []string{"MAKEFLAGS=-i"}},
		{"BASH_ENV=/dev/null, --workflow", true, []string{"BASH_ENV=/dev/null"}},
		{"BASH_ENV=/dev/null, local", false, []string{"BASH_ENV=/dev/null"}},
		{"ENV=/dev/null, --workflow", true, []string{"ENV=/dev/null"}},
		{"GNUMAKEFLAGS=-i, --workflow", true, []string{"GNUMAKEFLAGS=-i"}},
		{"VERSION=x (a Makefile ?= variable), --workflow", true, []string{"VERSION=x"}},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			args := []string{filepath.Join(root, "scripts", "make-integrity-guard.py")}
			if tc.workflow {
				args = append(args, "--workflow")
			}
			out, code := run(t, root, cleanEnv(tc.env...), "python3", args...)
			if code == 0 || !strings.Contains(out, "make was NOT invoked (0 make process(es) started)") {
				t.Fatalf("exit %d; want a refusal with no make process started:\n%s", code, out)
			}
			t.Logf("%s | exit %d: %s", tc.name, code, firstFail(out))
		})
	}
}

// R-3 and the ci-required parity: a symlinked Makefile, and case-variant
// siblings, are refused by the anchor before make AND by ci-required-guard.
func TestPinnedFilesMustBeRegularAndAloneInBothReaders(t *testing.T) {
	requirePython(t)
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, dir string)
		want  string
	}{
		{"Makefile is a symlink to identical bytes", func(t *testing.T, dir string) {
			mk := filepath.Join(dir, "Makefile")
			if err := os.Rename(mk, filepath.Join(dir, "Makefile.real")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("Makefile.real", mk); err != nil {
				t.Fatal(err)
			}
		}, "is not a regular file"},
		{"an unpinned GNUmakefile", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "GNUmakefile"), []byte("ci:\n\t@true\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "gnumakefile exists beside the makefile"},
		{"a pinned file that is missing", func(t *testing.T, dir string) {
			pin := filepath.Join(dir, ".github", "pinned-makefiles.yml")
			raw, _ := os.ReadFile(pin)
			extra := "  gone.mk: " + strings.Repeat("0", 64) + "\n"
			if err := os.WriteFile(pin, append(raw, []byte(extra)...), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "gone.mk is pinned in"},
		{"a stale pin entry (a pinned file make would not read)", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "unused.mk"), []byte("X := 1\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			pin := filepath.Join(dir, ".github", "pinned-makefiles.yml")
			raw, _ := os.ReadFile(pin)
			extra := "  unused.mk: " + digest([]byte("X := 1\n")) + "\n"
			if err := os.WriteFile(pin, append(raw, []byte(extra)...), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "which make would not read"},
		{"a case-variant GNUMakefile", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "GNUMakefile"), []byte("ci:\n\t@true\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}, "gnumakefile exists beside the makefile"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := copyTree(t)
			tc.setup(t, dir)
			out, code := anchor(t)(dir, cleanEnv())
			if code == 0 || !strings.Contains(strings.ToLower(out), tc.want) || !strings.Contains(out, "make was NOT invoked") {
				t.Fatalf("anchor: exit %d, want %q before make:\n%s", code, tc.want, out)
			}
			gout, gcode := guardPy(t)(dir, cleanEnv())
			if gcode == 0 || !strings.Contains(strings.ToLower(gout), tc.want) {
				t.Fatalf("ci-required-guard: exit %d, want %q:\n%s", gcode, tc.want, gout)
			}
			t.Logf("%s | anchor exit %d before make; ci-required-guard exit %d: %s", tc.name, code, gcode, firstFail(out))
		})
	}
}

// R-1's inventory. make may be started only by scripts/makegate.py (the gate)
// and by the pinned workflow steps (each one guarded by the adjacent anchor).
// This test fails on any make call it MATCHES outside makegate.py, and it
// matches exactly these forms (AGENTS.md lists the same, and what it does not
// match):
//
//   - .go, parsed with go/ast: an os/exec Command/CommandContext call —
//     os/exec imported as `exec`, under an alias, or dot-imported (a bare
//     Command/CommandContext call) — with a string literal in ANY argument
//     that is make or gmake (any path), or a shell line with make in command
//     position;
//   - .py, parsed with Python's ast: (a) a call to any function of the
//     subprocess module, or to an os function whose name starts system /
//     popen / exec / spawn / posix_spawn — imported as a module (any alias),
//     by `from … import name [as alias]`, or by `from … import *` (then the
//     bare names run, call, check_call, check_output, Popen, getoutput,
//     getstatusoutput, or the os prefixes above) — with, anywhere in its
//     arguments, a string that is make/gmake (any path; so ["env", "make", …]
//     too) or has make in shell command position (shell=True, os.system), or
//     a name make/gmake; and (b) ANYWHERE in the file, a list or tuple literal
//     whose first element is the string make/gmake (any path), so an argv
//     held in a variable (ARGV = ["make", "ci"]) is matched where it is
//     written;
//   - .sh, per line: make in command position (makeShellPattern).
//
// Not matched, so review-only: make named through a variable or constant in
// any other way, a wrapper script, other exec APIs and dynamic lookups
// (getattr, importlib), the line positions makeShellPattern does not list,
// and files without those extensions or under docs/, .git/, testdata/, bin/,
// node_modules/. A .go or .py file that does not parse is a failure, not a
// pass.
//
// makeShellPattern is make in shell command position: at the start, or after
// ; & && | || ( ` { ! or then/do/if/elif/else/while/until/time, optionally
// behind VAR=value words and exec/command (no flags) or env/nohup/sudo (with
// flags, each flag optionally followed by ONE separate argument that does
// not start with `-`, and VAR=value words), with any path. RE2 and Python's
// re agree on it; the Python scan receives it as an argument, so there is
// one definition.
const makeShellPattern = "(?:^|[;&|(`{!]|\\b(?:then|do|if|elif|else|while|until|time)\\s)\\s*" +
	"(?:[A-Za-z_][A-Za-z0-9_]*=\\S*\\s+)*" +
	"(?:(?:exec|command)\\s+|(?:env|nohup|sudo)\\s+(?:-\\S+(?:\\s+[^-\\s]\\S*)?\\s+)*(?:[A-Za-z_][A-Za-z0-9_]*=\\S*\\s+)*)*" +
	"(?:\\S*/)?g?make(?:\\s|$|[;&|)`}])"

var (
	makeShell   = regexp.MustCompile(makeShellPattern)
	makeProgram = regexp.MustCompile(`^(?:.*/)?g?make$`)
)

// pyMakeCalls is the Python half of the inventory: argv[1] is makeShellPattern,
// the rest are .py files. It prints JSON: [{"path", "line"}] per matched call,
// and {"path", "error"} for a file it cannot parse.
const pyMakeCalls = `
import ast, json, re, sys
SH = re.compile(sys.argv[1])
PROG = re.compile(r"^(?:.*/)?g?make$")
OS_FUNCS = ("system", "popen", "exec", "spawn", "posix_spawn")
SUBPROCESS_STAR = ("run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput")
out = []
for path in sys.argv[2:]:
    try:
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), path)
    except (SyntaxError, UnicodeDecodeError, ValueError) as err:
        out.append({"path": path, "line": 0, "error": str(err)})
        continue
    mods, funcs, star = {}, {}, set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name in ("subprocess", "os"):
                    mods[a.asname or a.name] = a.name
        elif isinstance(node, ast.ImportFrom) and node.module in ("subprocess", "os"):
            for a in node.names:
                if a.name == "*":
                    star.add(node.module)
                else:
                    funcs[a.asname or a.name] = (node.module, a.name)
    covered = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f, target = node.func, None
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in mods:
            target = (mods[f.value.id], f.attr)
        elif isinstance(f, ast.Name) and f.id in funcs:
            target = funcs[f.id]
        elif isinstance(f, ast.Name) and "subprocess" in star and f.id in SUBPROCESS_STAR:
            target = ("subprocess", f.id)
        elif isinstance(f, ast.Name) and "os" in star and f.id.startswith(OS_FUNCS):
            target = ("os", f.id)
        if target is None or (target[0] == "os" and not target[1].startswith(OS_FUNCS)):
            continue
        hit = False
        for arg in list(node.args) + [k.value for k in node.keywords]:
            for sub in ast.walk(arg):
                covered.add(id(sub))
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    hit = hit or bool(PROG.match(sub.value) or SH.search(sub.value))
                elif isinstance(sub, ast.Name):
                    hit = hit or sub.id in ("make", "gmake")
        if hit:
            out.append({"path": path, "line": node.lineno, "error": ""})
    # An argv written as a literal anywhere else in the file (ARGV = ["make", "ci"]) is matched where
    # it is written; one inside a call's arguments was judged with that call above.
    for node in ast.walk(tree):
        if isinstance(node, (ast.List, ast.Tuple)) and node.elts and id(node) not in covered:
            first = node.elts[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str) and PROG.match(first.value):
                out.append({"path": path, "line": node.lineno, "error": ""})
seen, uniq = set(), []
for h in out:
    key = (h["path"], h["line"], h["error"])
    if key not in seen:
        seen.add(key)
        uniq.append(h)
json.dump(uniq, sys.stdout)
`

// goMakeCalls returns the line of every os/exec Command/CommandContext call in
// src that names make (see makeShellPattern for the shell form).
func goMakeCalls(path string, src []byte) ([]int, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	execNames := map[string]bool{"exec": true}
	dotExec := false
	for _, imp := range f.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == "os/exec" && imp.Name != nil {
			if imp.Name.Name == "." {
				dotExec = true
			} else {
				execNames[imp.Name.Name] = true
			}
		}
	}
	var lines []int
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fn := call.Fun.(type) {
		case *ast.SelectorExpr:
			if fn.Sel.Name != "Command" && fn.Sel.Name != "CommandContext" {
				return true
			}
			if x, ok := fn.X.(*ast.Ident); !ok || !execNames[x.Name] {
				return true
			}
		case *ast.Ident: // a dot-import of os/exec
			if !dotExec || (fn.Name != "Command" && fn.Name != "CommandContext") {
				return true
			}
		default:
			return true
		}
		hit := false
		for _, a := range call.Args {
			ast.Inspect(a, func(m ast.Node) bool {
				if lit, ok := m.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					if v, err := strconv.Unquote(lit.Value); err == nil && (makeProgram.MatchString(v) || makeShell.MatchString(v)) {
						hit = true
					}
				}
				return true
			})
		}
		if hit {
			lines = append(lines, fset.Position(call.Pos()).Line)
		}
		return true
	})
	return lines, nil
}

// makeLaunchSites walks root as the inventory does and returns every matched
// site as "rel:line", plus the files it could not read (a failure, never a pass).
func makeLaunchSites(t *testing.T, root string) (sites, problems []string) {
	t.Helper()
	var pyFiles []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			switch d.Name() {
			case ".git", "bin", "docs", "testdata", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".go":
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			lines, err := goMakeCalls(path, raw)
			if err != nil {
				problems = append(problems, fmt.Sprintf("%s does not parse, so it is not cleared: %v", rel, err))
			}
			for _, n := range lines {
				sites = append(sites, fmt.Sprintf("%s:%d", rel, n))
			}
		case ".py":
			pyFiles = append(pyFiles, path)
		case ".sh":
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for n, line := range strings.Split(string(raw), "\n") {
				if strings.HasPrefix(strings.TrimSpace(line), "#") {
					continue
				}
				if makeShell.MatchString(line) {
					sites = append(sites, fmt.Sprintf("%s:%d", rel, n+1))
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(pyFiles) > 0 {
		cmd := exec.Command("python3", append([]string{"-c", pyMakeCalls, makeShellPattern}, pyFiles...)...)
		cmd.Env = cleanEnv()
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("BLOCKED: the Python half of the inventory did not run: %v\n%s", err, out)
		}
		var found []struct {
			Path  string `json:"path"`
			Line  int    `json:"line"`
			Error string `json:"error"`
		}
		if err := json.Unmarshal(out, &found); err != nil {
			t.Fatalf("the Python half of the inventory printed something that is not its JSON: %v\n%s", err, out)
		}
		for _, h := range found {
			rel, _ := filepath.Rel(root, h.Path)
			rel = filepath.ToSlash(rel)
			if h.Error != "" {
				problems = append(problems, fmt.Sprintf("%s does not parse, so it is not cleared: %s", rel, h.Error))
				continue
			}
			sites = append(sites, fmt.Sprintf("%s:%d", rel, h.Line))
		}
	}
	sort.Strings(sites)
	return sites, problems
}

func TestEveryPlaceThatStartsMakeIsGated(t *testing.T) {
	requirePython(t)
	root := repoRoot(t)
	sites, problems := makeLaunchSites(t, root)
	for _, p := range problems {
		t.Errorf("%s", p)
	}
	for _, s := range sites {
		if !strings.HasPrefix(s, "scripts/makegate.py:") {
			t.Errorf("%s starts make outside scripts/makegate.py", s)
		}
	}
	if len(sites) == 0 {
		t.Fatal("the inventory found no make call at all, not even makegate.py's own: the scan is not reading the tree")
	}
	t.Logf("every place the inventory matches that starts make: %v (allowed: scripts/makegate.py)", sites)
}

// Every form the inventory claims to match, planted as a real file in an
// otherwise empty tree: each must be reported at its own line. The controls
// that must NOT be reported keep the patterns from matching everything. The
// planted files are never run.
func TestTheMakeLaunchInventorySeesEveryListedForm(t *testing.T) {
	requirePython(t)
	const goHead = "package p\n\nimport (\n\t\"context\"\n\t\"os/exec\"\n)\n\nfunc f(ctx context.Context) {\n"
	const goLine = 9 // the first line of f's body
	type form struct{ name, file, src string }
	hits := []form{
		{"go exec.Command", "a.go", goHead + "\t_ = exec.Command(\"make\", \"ci\")\n}\n"},
		{"go exec.CommandContext after ctx", "a.go", goHead + "\t_ = exec.CommandContext(ctx, \"make\", \"ci\")\n}\n"},
		{"go an absolute path", "a.go", goHead + "\t_ = exec.Command(\"/usr/local/bin/make\", \"ci\")\n}\n"},
		{"go gmake", "a.go", goHead + "\t_ = exec.Command(\"gmake\", \"ci\")\n}\n"},
		{"go through a shell", "a.go", goHead + "\t_ = exec.CommandContext(ctx, \"sh\", \"-c\", \"cd x && make ci\")\n}\n"},
		{"go the call split across lines", "a.go", goHead + "\t_ = exec.CommandContext(\n\t\tctx,\n\t\t\"make\",\n\t)\n}\n"},
		{"go an aliased os/exec import", "a.go", "package p\n\nimport osexec \"os/exec\"\n\nfunc f() {\n\t_ = 0\n\t_ = 0\n\t_ = 0\n\t_ = osexec.Command(\"make\")\n}\n"},
		{"py a subprocess list", "a.py", "import subprocess\n\n\n\n\n\n\n\nsubprocess.run([\"make\", \"ci\"])\n"},
		{"py shell=True", "a.py", "import subprocess\n\n\n\n\n\n\n\nsubprocess.run(\"make ci\", shell=True)\n"},
		{"py os.system", "a.py", "import os\n\n\n\n\n\n\n\nos.system(\"cd x && make ci\")\n"},
		{"py env make", "a.py", "import subprocess\n\n\n\n\n\n\n\nsubprocess.run([\"env\", \"make\", \"ci\"])\n"},
		{"py os.execvp", "a.py", "import os\n\n\n\n\n\n\n\nos.execvp(\"make\", [\"make\", \"ci\"])\n"},
		{"py a from-import alias", "a.py", "from subprocess import check_call as cc\n\n\n\n\n\n\n\ncc([\"/usr/bin/make\", \"ci\"])\n"},
		{"py a module alias", "a.py", "import subprocess as sp\n\n\n\n\n\n\n\nsp.Popen([\"gmake\"])\n"},
		{"py the name make in argv", "a.py", "import subprocess\n\n\n\nmake = '/usr/bin/make'\n\n\n\nsubprocess.run([make, 'ci'])\n"},
		{"py the list split across lines", "a.py", "import subprocess\n\n\n\n\n\n\n\nsubprocess.run(\n    [\n        \"make\",\n    ]\n)\n"},
		{"sh at the start", "a.sh", "#!/bin/sh\n\n\n\n\n\n\n\nmake ci\n"},
		{"sh behind an assignment", "a.sh", "#!/bin/sh\n\n\n\n\n\n\n\nFOO=1 make ci\n"},
		{"sh after &&", "a.sh", "#!/bin/sh\n\n\n\n\n\n\n\ncd x && make ci\n"},
		{"sh after ||", "a.sh", "#!/bin/sh\n\n\n\n\n\n\n\ntrue || make ci\n"},
		{"sh after ;", "a.sh", "#!/bin/sh\n\n\n\n\n\n\n\ncd x; make ci\n"},
		{"sh after |", "a.sh", "#!/bin/sh\n\n\n\n\n\n\n\necho ci | make -f -\n"},
		{"sh in a subshell", "a.sh", "#!/bin/sh\n\n\n\n\n\n\n\n(make ci)\n"},
		{"sh in $( )", "a.sh", "#!/bin/sh\n\n\n\n\n\n\n\nout=$(make -n ci)\n"},
		{"sh after if", "a.sh", "#!/bin/sh\n\n\n\n\n\n\n\nif make -q ci; then :; fi\n"},
		{"sh after if !", "a.sh", "#!/bin/sh\n\n\n\n\n\n\n\nif ! make -q ci; then :; fi\n"},
		{"sh after then", "a.sh", "#!/bin/sh\n\n\n\n\n\n\n\nif true; then make ci; fi\n"},
		{"sh after do", "a.sh", "#!/bin/sh\n\n\n\n\n\n\n\nfor x in 1; do make ci; done\n"},
		{"sh an absolute path", "a.sh", "#!/bin/sh\n\n\n\n\n\n\n\n/usr/local/bin/make ci\n"},
		{"sh behind env with flags", "a.sh", "#!/bin/sh\n\n\n\n\n\n\n\nenv -i PATH=/usr/bin make ci\n"},
		{"sh behind exec", "a.sh", "#!/bin/sh\n\n\n\n\n\n\n\nexec make ci\n"},
		// PR #5 closing re-verification, FINDING 6 and 8.
		{"sh behind env -u NAME (a flag with an argument)", "a.sh", "#!/bin/sh\n\n\n\n\n\n\n\nenv -u X make ci\n"},
		{"sh behind sudo -u user", "a.sh", "#!/bin/sh\n\n\n\n\n\n\n\nsudo -u bob make ci\n"},
		{"go a dot-import of os/exec", "a.go", "package p\n\nimport . \"os/exec\"\n\nfunc f() {\n\t_ = 0\n\t_ = 0\n\t_ = 0\n\t_ = Command(\"make\")\n}\n"},
		{"py from subprocess import *", "a.py", "from subprocess import *\n\n\n\n\n\n\n\nrun([\"make\", \"ci\"])\n"},
		{"py from os import *", "a.py", "from os import *\n\n\n\n\n\n\n\nsystem(\"make ci\")\n"},
		{"py an argv list held in a variable", "a.py", "import subprocess\n\n\n\n\n\n\n\nARGV = [\"make\", \"ci\"]\nsubprocess.run(ARGV)\n"},
		{"py an argv tuple held in a variable", "a.py", "\n\n\n\n\n\n\n\nARGV = (\"/usr/bin/gmake\",)\n"},
	}
	misses := []form{
		{"go a commented-out call", "a.go", goHead + "\t// _ = exec.Command(\"make\")\n}\n"},
		{"go make in a non-exec call", "a.go", "package p\n\nimport \"fmt\"\n\nfunc f() { fmt.Println(\"make ci\") }\n"},
		{"go a non-make program", "a.go", goHead + "\t_ = exec.Command(\"python3\", \"scripts/makegate.py\", \"--\", \"-n\")\n}\n"},
		{"py make in a message", "a.py", "print(\"run make ci\")\n"},
		{"py a subprocess call without make", "a.py", "import subprocess\nsubprocess.run([\"git\", \"log\"])\n"},
		{"py a commented-out call", "a.py", "import subprocess\n# subprocess.run(['make'])\n"},
		{"sh a comment", "a.sh", "# make ci\n"},
		{"sh make as an argument", "a.sh", "echo make ci\n"},
		{"sh a make-prefixed script", "a.sh", "./scripts/make-integrity-guard.sh --workflow\n"},
		{"sh command -v make", "a.sh", "command -v make >/dev/null\n"},
		{"sh env -u NAME then a non-make program", "a.sh", "env -u X printf make\n"},
		{"py a list whose first element is not make", "a.py", "X = [\"git\", \"make\"]\n"},
		{"py a bare run() without a star-import", "a.py", "def run(x):\n    pass\nrun(\"make ci\")\n"},
	}
	for _, f := range hits {
		f := f
		t.Run("matched/"+f.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, f.file), []byte(f.src), 0o644); err != nil {
				t.Fatal(err)
			}
			sites, problems := makeLaunchSites(t, dir)
			want := fmt.Sprintf("%s:%d", f.file, goLine)
			if len(problems) != 0 || len(sites) != 1 || sites[0] != want {
				t.Fatalf("planted %q: sites %v, problems %v; want exactly [%s]", f.src, sites, problems, want)
			}
			t.Logf("%s | planted and reported at %s", f.name, sites[0])
		})
	}
	for _, f := range misses {
		f := f
		t.Run("not matched/"+f.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, f.file), []byte(f.src), 0o644); err != nil {
				t.Fatal(err)
			}
			sites, problems := makeLaunchSites(t, dir)
			if len(problems) != 0 || len(sites) != 0 {
				t.Fatalf("control %q: sites %v, problems %v; want none", f.src, sites, problems)
			}
		})
	}
	for _, f := range []form{
		{"go that does not parse", "a.go", "package p\nfunc (\n"},
		{"py that does not parse", "a.py", "def (:\n"},
	} {
		f := f
		t.Run("fails closed/"+f.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, f.file), []byte(f.src), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, problems := makeLaunchSites(t, dir); len(problems) != 1 || !strings.Contains(problems[0], "does not parse") {
				t.Fatalf("an unparsable %s was not reported: %v", f.file, problems)
			}
		})
	}
}

// The chair's correction to core #10's probe: ONE `make -q` naming EVERY pinned
// file, because -q applies in the remake phase only to makefiles named on the
// command line and a newer `inc.mk.sh` could otherwise remake a pinned include.
// Since the closing slice's fix round 2 the Makefile GRAMMAR refuses `include`
// outright (makegate.grammar_problems), so a pinned include never reaches make
// at all: the control that used to pass ("a reviewed Makefile with a pinned
// include") is now refused before make, and the newer sibling still leaves
// inc.mk byte-identical. The one-invocation probe itself is still what the
// anchor runs for the pinned Makefile (TestTheAnchorRefusesAPinnedMakefileMakeWouldRemake).
func TestTheRemakeProbeCoversEveryPinnedInclude(t *testing.T) {
	requirePython(t)
	dir := copyTree(t)
	const flagsPin = ".SHELLFLAGS := -eu -o pipefail -c\n"
	mk := filepath.Join(dir, "Makefile")
	raw, _ := os.ReadFile(mk)
	if strings.Count(string(raw), flagsPin) != 1 {
		t.Fatal("the Makefile no longer has the line this case edits")
	}
	if err := os.WriteFile(mk, []byte(strings.Replace(string(raw), flagsPin, flagsPin+"include inc.mk\n", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	inc := []byte("INCLUDED_BY_REVIEW := 1\n")
	if err := os.WriteFile(filepath.Join(dir, "inc.mk"), inc, 0o644); err != nil {
		t.Fatal(err)
	}
	repin(t, dir)
	pin := filepath.Join(dir, ".github", "pinned-makefiles.yml")
	p, _ := os.ReadFile(pin)
	if err := os.WriteFile(pin, append(p, []byte("  inc.mk: "+digest(inc)+"\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, code := anchor(t)(dir, cleanEnv()); code == 0 || !strings.Contains(out, "the `include` directive") ||
		!strings.Contains(out, "make was NOT invoked (0 make process(es) started)") {
		t.Fatalf("a reviewed, pinned include: exit %d; want it refused by the grammar before make:\n%s", code, out)
	}
	plantNewerSibling(t, dir, "inc.mk.sh")
	// plantNewerSibling dates the sibling from the Makefile; date it from inc.mk too.
	info, _ := os.Stat(filepath.Join(dir, "inc.mk"))
	future := info.ModTime().Add(48 * time.Hour)
	if err := os.Chtimes(filepath.Join(dir, "inc.mk.sh"), future, future); err != nil {
		t.Fatal(err)
	}
	out, code := anchor(t)(dir, cleanEnv())
	after, _ := os.ReadFile(filepath.Join(dir, "inc.mk"))
	if digest(after) != digest(inc) {
		t.Fatalf("make REWROTE the pinned include inc.mk:\n%s", out)
	}
	if code == 0 || !strings.Contains(out, "make was NOT invoked (0 make process(es) started)") {
		t.Fatalf("exit %d; want the include refused before make, with the newer sibling present:\n%s", code, out)
	}
	t.Logf("pinned include + newer inc.mk.sh | anchor exit %d, 0 make processes: %s | inc.mk sha256 %s unchanged",
		code, firstFail(out), digest(inc)[:12])
}

// Chair note from core PR #10's re-verification: on GNU Make 4.3 a pinned
// `.RECIPEPREFIX := >` with a recipe `> -cmd` hides the `-` prefix from every
// tab-keyed check. So even in REVIEWED, re-pinned bytes, a `.RECIPEPREFIX`
// assignment (any spelling) and `.SECONDEXPANSION` are refused by name from the
// pinned read set BEFORE make, with zero make processes started. The `-cmd`
// recipe here is a plain `-true`; nothing is built to exploit it.
func TestNamedMakefileConstructsAreRefusedBeforeMake(t *testing.T) {
	requirePython(t)
	for _, tc := range []struct{ name, add, want string }{
		{".RECIPEPREFIX := > with a > -true recipe", "\n.RECIPEPREFIX := >\nextra-target:\n> -true\n", "assigns `.recipeprefix`"},
		{"override .RECIPEPREFIX = >", "\noverride .RECIPEPREFIX = >\n", "assigns `.recipeprefix`"},
		{"define .RECIPEPREFIX", "\ndefine .RECIPEPREFIX\n>\nendef\n", "assigns `.recipeprefix`"},
		{".SECONDEXPANSION:", "\n.SECONDEXPANSION:\n", "declares `.secondexpansion`"},
		// Chair note (core #10 re-verification): each of these ignores a gate failure, runs something
		// while make reads the file, or changes what the anchor's readings mean. Inert fixtures only.
		{".ONESHELL:", "\n.ONESHELL:\n", "declares `.oneshell`"},
		{".IGNORE: (all targets)", "\n.IGNORE:\n", "declares `.ignore`"},
		{".IGNORE: test", "\n.IGNORE: test\n", "declares `.ignore`"},
		{".DEFAULT:", "\n.DEFAULT: ; @true\n", "declares `.default`"},
		{".POSIX:", "\n.POSIX:\n", "declares `.posix`"},
		{".EXTRA_PREREQS", "\n.EXTRA_PREREQS := nothing\n", "assigns `.extra_prereqs`"},
		{"target-specific .EXTRA_PREREQS", "\ntest: .EXTRA_PREREQS := nothing\n", "assigns `.extra_prereqs`"},
		{"SHELL := /usr/bin/true", "\nSHELL := /usr/bin/true\n", "assigns `shell`"},
		{".SHELLFLAGS := -c", "\n.SHELLFLAGS := -c\n", "assigns `.shellflags`"},
		{"MAKEFLAGS += -i", "\nMAKEFLAGS += -i\n", "assigns `makeflags`"},
		{"GNUMAKEFLAGS += -i", "\nGNUMAKEFLAGS += -i\n", "assigns `gnumakeflags`"},
		{"MFLAGS = -i", "\nMFLAGS = -i\n", "assigns `mflags`"},
		{"target-specific MAKEFLAGS", "\ntest: MAKEFLAGS += -i\n", "assigns `makeflags`"},
		{"pattern-specific SHELL", "\n%: SHELL := /usr/bin/true\n", "assigns `shell`"},
		{"target-specific private SHELL", "\ntest: private SHELL = /bin/sh\n", "assigns `shell`"},
		{"override .SHELLFLAGS", "\noverride .SHELLFLAGS := -c\n", "assigns `.shellflags`"},
		{"define MAKEFLAGS", "\ndefine MAKEFLAGS\n-i\nendef\n", "assigns `makeflags`"},
		{"$(eval …)", "\n$(eval INERT := 1)\n", "calls $(eval"},
		{"+ recipe line", "\ninert-target:\n\t+@true\n", "prefixed `+`"},
		{"$(MAKE) in a recipe", "\ninert-target:\n\t@echo $(MAKE) >/dev/null\n", "names $(make)"},
		{"recipe that begins with an expansion", "\nQ := @\ninert-target:\n\t$(Q)true\n", "begins with an expansion"},
		// M-3 (security desk review at e068e07): make also expands `$` + ONE character — an automatic
		// variable or a one-letter name — and applies a `-`/`+` prefix produced that way. Inert: none runs.
		{"recipe that begins with $@", "\ninert-target:\n\t$@-is-not-run\n", "begins with an expansion"},
		{"recipe that begins with $<", "\ninert-target:\n\t$<true\n", "begins with an expansion"},
		{"recipe that begins with $X (a one-letter variable)", "\nX := @\ninert-target:\n\t$Xtrue\n", "begins with an expansion"},
		// PR #5 closing re-verification, FINDING 5: every recipe must be a TAB line after a SIMPLE rule
		// line, or the TAB-keyed checks and the anchor's `<target>:` reading do not see it. Inert.
		{"inline ; recipe with a - prefix", "\ninert-target: ; -true\n", "inline `;` recipe"},
		{"inline ; recipe beginning with $@", "\ninert-target: ; $@x\n", "inline `;` recipe"},
		{"inline ; recipe with a + prefix", "\ninert-target: ; +true\n", "inline `;` recipe"},
		{"two targets on one rule line, a gate target second", "\ninert-target test:\n\t-true\n", "more than one target"},
		{"grouped targets &:", "\ninert-a inert-b &:\n\t@true\n", "more than one target"},
		{"a special target that is not the first word", "\ninert-target .IGNORE:\n", "more than one target"},
		{"a rule target that is an expansion ($(I)ORE:)", "\n$(I)ORE: test\n", "target name is an expansion"},
		{"a rule line that starts with whitespace", "\n  inert-target:\n\t-true\n", "starts with whitespace"},
		{"a rule line continued with a backslash", "\ninert-target \\\n  :\n\t-true\n", "continued with a backslash"},
		// M-2, refused rather than narrowed: a variable NAME that is an expansion, in every assigning position.
		{"a computed variable name, global", "\n$(M)AKEFLAGS += -i\n", "assigns a variable whose name is an expansion"},
		{"a computed variable name, target-specific", "\ntest: $(S)HELL = /bin/sh\n", "assigns a variable whose name is an expansion"},
		{"define with a computed name", "\ndefine $(M)AKEFLAGS\n-i\nendef\n", "defines a variable whose name is an expansion"},
		{"$(call eval,…)", "\nINERT := $(call eval,INERT2 := 1)\n", "calls $(eval"},
		// THE GRAMMAR (chair ruling after the closing re-verification at 888a51b): every line outside the
		// allowed shapes is refused by line number, whatever its spelling. FINDING 9-12 first, then other
		// lines outside the grammar. Inert: nothing here is run.
		{"F9 inline recipe holding = (-run=Foo)", "\ninert-target: ; -go test -run=Foo ./...\n", "outside the makefile grammar"},
		{"F9 inline recipe with a prerequisite, holding X=1", "\ninert-target: dep ; -false X=1\n", "outside the makefile grammar"},
		{"F9 inline recipe echo a=b", "\ninert-target: ; @echo a=b\n", "outside the makefile grammar"},
		{"F10 a non-TAB line inside a conditional within a recipe", "\ninert-target:\n\ttrue\nifeq (a,b)\nINERT := 1\nendif\n\t-false\n", "outside the makefile grammar"},
		{"a conditional within a recipe (moved from the reading rows)", "\ninert-target:\n\ttrue\nifndef VIZRA_NEVER_SET\n\t-true\nendif\n", "outside the makefile grammar"},
		{"F11 private rule line with an inline recipe", "\nprivate inert-target: ; -true\n", "outside the makefile grammar"},
		{"F11 override rule line with an inline recipe", "\noverride inert-target: ; -true\n", "outside the makefile grammar"},
		{"F11 private rule line with a TAB recipe", "\nprivate inert-target:\n\t-true\n", "outside the makefile grammar"},
		{"F11 undefine rule line", "\nundefine inert-target: ; -true\n", "outside the makefile grammar"},
		{"F11 load rule line", "\nload inert-target: ; -true\n", "outside the makefile grammar"},
		{"F12 call with a partly computed function name", "\nINERT := $(call ev$(A)al,x)\n", "outside the makefile grammar"},
		{"grammar: include", "\ninclude inert.mk\n", "outside the makefile grammar"},
		{"grammar: define", "\ndefine INERT\nx\nendef\n", "outside the makefile grammar"},
		{"grammar: export", "\nexport INERT\n", "outside the makefile grammar"},
		{"grammar: vpath", "\nvpath %.c src\n", "outside the makefile grammar"},
		{"grammar: a conditional", "\nifeq (a,b)\nendif\n", "outside the makefile grammar"},
		{"grammar: a second colon", "\ninert-target: a: b\n", "outside the makefile grammar"},
		{"grammar: a double-colon rule", "\ninert-target:: a\n", "outside the makefile grammar"},
		{"grammar: a pattern rule", "\n%.o: %.c\n", "outside the makefile grammar"},
		{"grammar: a special target (.SILENT)", "\n.SILENT:\n", "outside the makefile grammar"},
		{"grammar: a += assignment", "\nINERT += 1\n", "outside the makefile grammar"},
		{"grammar: a TAB line outside a rule", "\nINERT := 1\n\t-true\n", "outside the makefile grammar"},
		{"grammar: a # inside $(shell …)", "\nINERT := $(shell echo # x)\n", "outside the makefile grammar"},
		{"grammar: a substitution reference in a value", "\nINERT := $(PKG:a=b)\n", "outside the makefile grammar"},
		{"grammar: a function in a value", "\nINERT := $(foreach f,a,b)\n", "outside the makefile grammar"},
		{"grammar: $X in a recipe", "\ninert-target:\n\techo $X\n", "outside the makefile grammar"},
		{"grammar: $(shell …) in a recipe", "\ninert-target:\n\techo $(shell true)\n", "outside the makefile grammar"},
		// FINDING 7's reference forms other than $(V)/${V}: refused before make, so they cannot read the environment.
		{"grammar: $V in a value", "\nINERT := $Q\n", "outside the makefile grammar"},
		{"grammar: $(origin V) in a value", "\nINERT := $(origin VZ_M4_ORIGIN)\n", "outside the makefile grammar"},
		{"grammar: $(value V) in a value", "\nINERT := $(value VZ_M4_VALUE)\n", "outside the makefile grammar"},
		{"grammar: ifdef V", "\nifdef VZ_M4_IFDEF\nendif\n", "outside the makefile grammar"},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := copyTree(t)
			mk := filepath.Join(dir, "Makefile")
			raw, _ := os.ReadFile(mk)
			if err := os.WriteFile(mk, append(raw, []byte(tc.add)...), 0o644); err != nil {
				t.Fatal(err)
			}
			repin(t, dir)
			out, code := anchor(t)(dir, cleanEnv())
			if code == 0 || !strings.Contains(strings.ToLower(out), tc.want) ||
				!strings.Contains(out, "make was NOT invoked (0 make process(es) started)") {
				t.Fatalf("exit %d; want %q refused with 0 make processes started:\n%s", code, tc.want, out)
			}
			gout, gcode := guardPy(t)(dir, cleanEnv())
			if gcode == 0 || !strings.Contains(strings.ToLower(gout), tc.want) {
				t.Fatalf("ci-required-guard: exit %d, want %q:\n%s", gcode, tc.want, gout)
			}
			t.Logf("%s (re-pinned) | anchor exit %d, 0 make processes: %s | ci-required-guard exit %d",
				tc.name, code, firstFail(out), gcode)
		})
	}
}

// The control for M-3's check: `$$` is make's escape for a literal `$` (a shell
// variable), not an expansion make performs, so a recipe that begins with it is
// NOT refused. Without this, "refuse every leading `$`" would pass the rows above.
func TestARecipeBeginningWithAnEscapedDollarIsNotRefused(t *testing.T) {
	requirePython(t)
	dir := copyTree(t)
	mk := filepath.Join(dir, "Makefile")
	raw, _ := os.ReadFile(mk)
	if err := os.WriteFile(mk, append(raw, []byte("\ninert-target:\n\t$$inert_shell_word\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	repin(t, dir)
	if out, code := anchor(t)(dir, cleanEnv()); code != 0 {
		t.Fatalf("anchor: exit %d on a recipe beginning with `$$`; want green:\n%s", code, out)
	}
	if out, code := guardPy(t)(dir, cleanEnv()); code != 0 {
		t.Fatalf("ci-required-guard: exit %d on a recipe beginning with `$$`; want green:\n%s", code, out)
	}
}

// makeEnvRecorder runs a gate caller (argv[1]) with subprocess.run wrapped, and
// prints, for every make process the caller starts, which of the names in
// argv[2] were in that process's environment. It records; it changes nothing.
const makeEnvRecorder = `
import os, runpy, subprocess, sys
real = subprocess.run
names = sys.argv[2].split(",")
def recording(argv, *a, **k):
    if isinstance(argv, (list, tuple)) and argv and os.path.basename(str(argv[0])) in ("make", "gmake"):
        env = k.get("env")
        got = [n for n in names if n in (os.environ if env is None else env)]
        print("MAKE-ENV " + " ".join(str(x) for x in argv[1:3]) + " | planted: " + (",".join(got) or "none"),
              file=sys.stderr, flush=True)
    return real(argv, *a, **k)
subprocess.run = recording
script = sys.argv[1]
sys.argv = [script] + sys.argv[3:]
runpy.run_path(script, run_name="__main__")
`

// M-4 (security desk review at e068e07): make imports an environment variable
// as a recursively expanded variable, so a planted VERSION is evaluated while
// the Makefile is read. contract-drift-guard.py opens the gate BEFORE the
// anchor in its job, and the lane test opens it where no anchor runs. So every
// make process makegate starts, for every caller, runs without the variables
// the pinned makefiles can read from the environment. Asserted per make
// process. FINDING 7 (closing re-verification): make reads an environment
// variable through more forms than `$(NAME)`/`${NAME}`. Since fix round 2 the
// Makefile grammar lets a pinned makefile write only `$(NAME)`/`${NAME}`, so
// `$V`, `$(V:a=b)`, `ifdef V`, `$(origin V)` and `$(value V)` are refused
// before make (rows "grammar: …" in TestNamedMakefileConstructsAreRefusedBeforeMake).
// The copy's re-pinned Makefile gains the grammatical forms: `$(V)`, `${V}`
// and a read before a later `:=`, which environment_taken does not see; all
// planted. Nothing in the block runs a command.
const envReferenceForms = "\n# inert fixture: the ways the grammar lets make read an environment variable\n" +
	"VZ_M4_READ := $(VZ_M4_PAREN) ${VZ_M4_BRACE} $(VZ_M4_EARLY)\n" +
	"VZ_M4_EARLY := later\n"

func TestEnvironmentTakenVariablesNeverReachMake(t *testing.T) {
	requirePython(t)
	planted := []string{"VERSION", "COMMIT", "CORE", "GOFLAGS", "VZ_M4_PAREN", "VZ_M4_BRACE", "VZ_M4_EARLY"}
	callers := map[string][]string{
		"contract-drift-guard.py recipe":          {"scripts/contract-drift-guard.py", "recipe"},
		"makegate.py -- --dry-run contract-drift": {"scripts/makegate.py", "--", "--dry-run", "--no-print-directory", "contract-drift"},
	}
	for name, argv := range callers {
		name, argv := name, argv
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := copyTreeWith(t, "api", "internal", "cmd", "go.mod", "go.sum")
			mk := filepath.Join(dir, "Makefile")
			raw, _ := os.ReadFile(mk)
			if err := os.WriteFile(mk, append(raw, []byte(envReferenceForms)...), 0o644); err != nil {
				t.Fatal(err)
			}
			repin(t, dir)
			extra := []string{"GOFLAGS=-mod=mod"}
			for _, n := range planted {
				if n != "GOFLAGS" {
					extra = append(extra, n+"=vz-m4-planted")
				}
			}
			args := append([]string{"-c", makeEnvRecorder, filepath.Join(dir, argv[0]), strings.Join(planted, ",")}, argv[1:]...)
			out, code := run(t, dir, cleanEnv(extra...), "python3", args...)
			if code != 0 {
				t.Fatalf("%s: exit %d with the variables planted; want the gate to pass:\n%s", name, code, out)
			}
			var makes []string
			for _, l := range strings.Split(out, "\n") {
				if strings.HasPrefix(l, "MAKE-ENV ") {
					makes = append(makes, l)
				}
			}
			if len(makes) < 2 {
				t.Fatalf("%s: recorded %d make process(es); want at least the remake probe and the run:\n%s", name, len(makes), out)
			}
			for _, l := range makes {
				if !strings.HasSuffix(l, "| planted: none") {
					t.Errorf("%s: a make process received a variable the Makefile can read from the environment: %s", name, l)
				}
			}
			if !t.Failed() {
				t.Logf("%s | %d make process(es), none received any of %v", name, len(makes), planted)
			}
		})
	}
}

// The grammar is not wider than it needs to be, and not narrower: the REAL
// Makefile, unchanged, fits it with zero problems, and every allowed shape is
// actually exercised (so the check is not passing because it classified
// nothing). The allowlist's refusals are TestNamedMakefileConstructsAreRefusedBeforeMake's
// "grammar"/F9-F12 rows.
func TestTheRealMakefileFitsTheGrammar(t *testing.T) {
	requirePython(t)
	root := repoRoot(t)
	prog := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("makegate", sys.argv[1] + "/scripts/makegate.py")
mg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mg)
problems = mg.grammar_problems("Makefile", open(sys.argv[1] + "/Makefile").read())
print(json.dumps({"problems": problems, "shapes": mg.grammar_problems.last_shapes, "recipe_functions": list(mg.RECIPE_FUNCTIONS)}))
`
	out, code := run(t, root, cleanEnv(), "python3", "-c", prog, root)
	if code != 0 {
		t.Fatalf("the grammar check did not run: exit %d\n%s", code, out)
	}
	var got struct {
		Problems        []string       `json:"problems"`
		Shapes          map[string]int `json:"shapes"`
		RecipeFunctions []string       `json:"recipe_functions"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("unreadable result: %v\n%s", err, out)
	}
	if len(got.Problems) != 0 {
		t.Fatalf("the real Makefile does not fit the grammar:\n%s", strings.Join(got.Problems, "\n"))
	}
	for _, shape := range []string{"blank/comment", "assignment", "phony", "rule", "recipe"} {
		if got.Shapes[shape] == 0 {
			t.Errorf("the real Makefile has no %q line, so this test does not show the grammar reads that shape: %v", shape, got.Shapes)
		}
	}
	if len(got.RecipeFunctions) != 0 {
		t.Errorf("RECIPE_FUNCTIONS is %v; AGENTS.md says it is empty because this Makefile calls no function in a recipe", got.RecipeFunctions)
	}
	if !t.Failed() {
		t.Logf("the real Makefile fits the grammar: %v; RECIPE_FUNCTIONS = %v", got.Shapes, got.RecipeFunctions)
	}
}
