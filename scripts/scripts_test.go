package scripts_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

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
	src := repoRoot(t)
	dst := t.TempDir()
	for _, rel := range []string{".github", "scripts", "Makefile", "Dockerfile"} {
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
		{name: "direct: step if:", file: ciYML, old: "      - name: nothing is skipped and every package meets its floor (Q-001), without make\n", new: "      - name: nothing is skipped and every package meets its floor (Q-001), without make\n        if: github.event_name == 'push'\n", want: "direct test step"},
		// --- the manifest, the floor, the pins, and their agreement (item 4) ---
		{name: "floor lane removed from manifest", file: manifest, old: "\nvendor-contract-selftest\n", new: "\n", want: "'vendor-contract-selftest' is missing"},
		{name: "floor lane commented out", file: manifest, old: "\ntest-noskip\n", new: "\n# test-noskip\n", want: "commented out"},
		{name: "manifest names no job", file: manifest, old: "\ndocker-build\n", new: "\ndocker-build\nno-such-lane\n", want: "matches no job"},
		{name: "required job removed from the workflow", file: ciYML, old: "  vendor-contract-selftest:\n    name: vendor-contract-selftest\n", new: "  vendor-contract-selftest-renamed:\n    name: vendor-contract-selftest-renamed\n", want: "'vendor-contract-selftest' matches no job"},
		{name: "lane dropped from make ci", file: "Makefile", old: " tidy-check vendor-contract-selftest ## Every required lane", new: " tidy-check ## Every required lane", want: "`ci:` and the required lanes disagree"},
		{name: "pins: unknown key", file: pinsYML, old: "", new: "\nextra_allowance: []\n", want: "unknown key"},
		{name: "pins: a body nothing requires", file: pinsYML, old: "  - |\n    make vendor-contract-selftest\n", new: "  - |\n    make vendor-contract-selftest\n  - |\n    make ci\n", want: "that no job is required to run"},
		{name: "Makefile edited, pin not updated", file: "Makefile", old: "SHELL := /bin/bash\n", new: "SHELL := /bin/bash \n", want: "does not match its pin"},
		{name: "makefile pin emptied", file: ".github/pinned-makefiles.yml", old: "\nMakefile: ", new: "\n# Makefile: ", want: "pins nothing"},
		{name: "makefile pin: Makefile not covered", file: ".github/pinned-makefiles.yml", old: "\nMakefile: ", new: "\nOther: ", want: "does not pin `makefile`"},
		{name: "makefile pin: not a sha256", file: ".github/pinned-makefiles.yml", old: "\nMakefile: ", new: "\nMakefile: x", want: "not `relative/path: <64 lowercase hex>`"},
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
		"the suite runs directly, without make, from a pinned body in lane(s) ['test-noskip']",
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
		if strings.HasPrefix(l, "Makefile: ") {
			lines[i] = "Makefile: " + digest(b)
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
		{name: "one byte changed", file: "Makefile", old: "SHELL := /bin/bash\n", new: "SHELL := /bin/bash \n", want: "does not match its pinned digest"},
		{name: "a comment added", file: "Makefile", old: "", new: "# harmless\n", want: "does not match its pinned digest"},
		{name: ".SECONDEXPANSION line (desk review FINDING 1)", file: "Makefile", old: flagsPin, new: flagsPin + ".SECONDEXPANSION:\n", want: "does not match its pinned digest"},
		{name: ".RECIPEPREFIX line (desk review FINDING 2)", file: "Makefile", old: "", new: ".RECIPEPREFIX := >\n", want: "does not match its pinned digest"},
		{name: "an include line", file: "Makefile", old: flagsPin, new: flagsPin + "include inc.mk\n", create: map[string]string{"inc.mk": "X := 1\n"}, want: "does not match its pinned digest"},
		{name: "the line that wrote the env file during the anchor", file: "Makefile", old: flagsPin, new: flagsPin + "POISON := $(shell echo MAKEFLAGS=-i >> \"$$GITHUB_ENV\")\n", want: "does not match its pinned digest"},
		{name: "the pin itself edited", file: ".github/pinned-makefiles.yml", old: "\nMakefile: ", new: "\nMakefile: 0", want: "is not a `path: <sha256>` pin"},
		{name: "the pin no longer covers Makefile", file: ".github/pinned-makefiles.yml", old: "\nMakefile: ", new: "\nOther: ", want: "does not pin `makefile`"},
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
	// include line had been reviewed: make then reads bytes nobody reviewed, and
	// MAKEFILE_LIST says so.
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
		if code == 0 || !strings.Contains(out, "make read ['Makefile', 'inc.mk']") {
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
		{name: "SHELL := /usr/bin/true", file: "Makefile", old: shellPin, new: "SHELL := /usr/bin/true\n", want: "shell"},
		{name: "MAKEFLAGS += -i", file: "Makefile", old: flagsPin, new: flagsPin + "MAKEFLAGS += -i\n", want: "assigns makeflags"},
		{name: "GNUMAKEFLAGS += -i", file: "Makefile", old: flagsPin, new: flagsPin + "GNUMAKEFLAGS += -i\n", want: "assigns gnumakeflags"},
		{name: ".SHELLFLAGS without -e", file: "Makefile", old: flagsPin, new: ".SHELLFLAGS := -c\n", want: ".shellflags"},
		{name: ".ONESHELL", file: "Makefile", old: flagsPin, new: flagsPin + ".ONESHELL:\n", want: "oneshell"},
		{name: ".SECONDEXPANSION", file: "Makefile", old: flagsPin, new: flagsPin + ".SECONDEXPANSION:\n", want: "declares `.secondexpansion`"},
		{name: ".RECIPEPREFIX", file: "Makefile", old: "", new: ".RECIPEPREFIX := >\n", want: "assigns `.recipeprefix`"},
		{name: "- prefix on the test recipe", file: "Makefile", old: testRecipe, new: "\t-go test -race -count=1 $(PKG)\n", want: "prefixed `-`"},
		{name: "|| true on the test recipe", file: "Makefile", old: testRecipe, new: "\tgo test -race -count=1 $(PKG) || true\n", want: "ending `|| true`"},
		{name: "; true on the test recipe", file: "Makefile", old: testRecipe, new: "\tgo test -race -count=1 $(PKG); true\n", want: "ending `; true`"},
		{name: "the exempt line in another target", file: "Makefile", old: "\tgo vet $(PKG)\n", new: "\tgo vet $(PKG)\n\tgo test -count=1 -json $(DRIFT_PKGS) > $(DRIFT_REPORT) || true\n", want: "ending `|| true`"},
		{name: "duplicate test target", file: "Makefile", old: "", new: "\ntest:\n\t@true\n", want: "defined 2 times"},
		{name: "test target inside a conditional", file: "Makefile", old: "test: ## Full test suite with the race detector\n" + testRecipe, new: "ifndef VIZRA_NEVER_SET\ntest: ## Full test suite with the race detector\n" + testRecipe + "endif\n", want: "conditional"},
		{name: "a NEW ?= variable, set in the environment", file: "Makefile", old: flagsPin, new: flagsPin + "GOCMD ?= go\n", env: []string{"GOCMD=true"}, want: "the environment sets gocmd='true'"},
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
			if !strings.Contains(out, "make runs only on reviewed bytes") {
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
		"make runs only on reviewed bytes: Makefile sha256",
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
