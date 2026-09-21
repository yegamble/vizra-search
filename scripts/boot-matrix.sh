#!/usr/bin/env bash
# boot-matrix.sh — the runtime-mode boot matrix, run against the REAL binary.
#
# One operator-facing name per concept: `VIZRA_MODE` is this process's runtime
# mode (development | production, production by default), and
# `VIZRA_SEARCH_MODE` is vizra-core's search TOPOLOGY (off | managed |
# external), which this service never reads as a mode.
#
# The matrix boots the compiled binary once per case and records what actually
# happened — not what a unit test believes happens. Every case that must BOOT is
# proved healthy over real TCP and then terminated; every case that must REFUSE
# is proved to exit non-zero with the offending variable named on stderr.
#
#   ./scripts/boot-matrix.sh                 # the matrix, on unmodified sources
#   ./scripts/boot-matrix.sh --mutate <name> # the matrix against one controlled
#                                            # mutation; the run MUST go red
#   ./scripts/boot-matrix.sh --list-mutations
#
# A mutation run records the sha256 of internal/config/config.go before and
# after, REFUSES TO PROCEED if the patch did not actually change the file, and
# restores the original on exit. A harness that would happily "demonstrate" an
# unapplied mutation proves nothing, so this one cannot.
#
# Exit codes: 0 the matrix passed; 1 a case failed; 2 the harness itself could
# not run (unapplied mutation, missing tool, build failure).

set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly REPO_ROOT
readonly TARGET="${REPO_ROOT}/internal/config/config.go"
readonly ENV_MODE="VIZRA_MODE"
readonly ENV_TOPOLOGY="VIZRA_SEARCH_MODE"
# Seconds a case that must REFUSE is allowed to live before the harness calls it
# booted. A refusal is a synchronous config check, so this is generous.
readonly REFUSAL_GRACE=10

MUTATION=""
WORK=""
BACKUP=""

die() { echo "boot-matrix: $*" >&2; exit 2; }

digest() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum   >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else die "no sha256sum or shasum on PATH"; fi
}

cleanup() {
  if [[ -n "${BACKUP}" && -f "${BACKUP}" ]]; then
    cp "${BACKUP}" "${TARGET}"
    echo "--- restored ${TARGET#"${REPO_ROOT}/"} (sha256 $(digest "${TARGET}"))"
  fi
  [[ -n "${WORK}" && -d "${WORK}" ]] && rm -rf "${WORK}"
  return 0
}
trap cleanup EXIT

# ----------------------------------------------------------------- mutations --
#
# Each mutation is an exact, single-occurrence replacement in config.go. Applying
# one is checked twice: the search text must occur exactly once, and the file
# digest must change. Both are what stops a demonstration that never happened.

mutation_names() { echo "fallback-to-the-old-name drop-the-refusal default-to-development"; }

mutation_describes() {
  case "$1" in
    fallback-to-the-old-name)
      echo "the refusal becomes a compatibility alias: the OLD name is read as the mode when ${ENV_MODE} is unset" ;;
    drop-the-refusal)
      echo "the old name is ignored instead of refused" ;;
    default-to-development)
      echo "an unset ${ENV_MODE} defaults to development instead of production" ;;
    *) return 1 ;;
  esac
}

# python3 does the replacement so the patterns can be multi-line and exact.
apply_mutation() {
  local name="$1"
  python3 - "$TARGET" "$name" <<'PY'
import sys

path, name = sys.argv[1], sys.argv[2]
src = open(path, encoding="utf-8").read()

# (search, replace) — the search text must occur exactly once.
PATCHES = {
    # The refusal for the old runtime vocabulary becomes a fallback: the value
    # is USED when the new name is absent. This is the "compatibility alias"
    # vizra-core's RetiredKeys comment says must not exist.
    "fallback-to-the-old-name": (
        "\tfor _, retired := range retiredModeValues {\n"
        "\t\tif value == retired {\n"
        "\t\t\tv.addf(",
        "\tfor _, retired := range retiredModeValues {\n"
        "\t\tif value == retired {\n"
        "\t\t\tif _, ok := v.raw(EnvMode); !ok {\n"
        "\t\t\t\tv.mutationFallbackMode = Mode(value)\n"
        "\t\t\t\treturn\n"
        "\t\t\t}\n"
        "\t\t\tv.addf(",
    ),
    # The old name is simply ignored, whatever it carries.
    "drop-the-refusal": (
        "\traw, ok := v.raw(EnvSearchTopology)\n"
        "\tif !ok || raw == \"\" {",
        "\traw, ok := v.raw(EnvSearchTopology)\n"
        "\tif true || !ok || raw == \"\" {",
    ),
    # Production is no longer the default.
    "default-to-development": (
        "\traw, ok := v.raw(EnvMode)\n"
        "\tif !ok || strings.TrimSpace(raw) == \"\" {\n"
        "\t\treturn ModeProduction\n"
        "\t}",
        "\traw, ok := v.raw(EnvMode)\n"
        "\tif !ok || strings.TrimSpace(raw) == \"\" {\n"
        "\t\treturn ModeDevelopment\n"
        "\t}",
    ),
}

if name not in PATCHES:
    sys.exit("unknown mutation " + name)
search, replace = PATCHES[name]
count = src.count(search)
if count != 1:
    sys.exit(f"mutation {name}: anchor text occurs {count} times, want exactly 1 — the harness refuses to guess")
src = src.replace(search, replace)

if name == "fallback-to-the-old-name":
    # The fallback needs somewhere to put the mode it stole, and mode() must
    # honour it, or the mutation would not be the mutation it claims to be.
    src = src.replace(
        "type validator struct {\n\tlookup   Lookup",
        "type validator struct {\n\tmutationFallbackMode Mode\n\tlookup   Lookup",
        1,
    )
    src = src.replace(
        "func (v *validator) mode() Mode {\n\traw, ok := v.raw(EnvMode)",
        "func (v *validator) mode() Mode {\n"
        "\tif v.mutationFallbackMode != \"\" {\n\t\treturn v.mutationFallbackMode\n\t}\n"
        "\traw, ok := v.raw(EnvMode)",
        1,
    )
    # searchTopology runs after mode() in LoadFrom, so the stolen mode has to be
    # taken before the Config is built for the mutation to be observable.
    src = src.replace(
        "\tv := &validator{lookup: lookup}\n\tcfg := &Config{",
        "\tv := &validator{lookup: lookup}\n\tv.searchTopology()\n\tcfg := &Config{",
        1,
    )
    src = src.replace("\tv.ceilings(cfg)\n\tv.searchTopology()", "\tv.ceilings(cfg)", 1)

open(path, "w", encoding="utf-8").write(src)
PY
}

# -------------------------------------------------------------------- cases --
#
# name | VIZRA_MODE | VIZRA_SEARCH_MODE | expectation
#   <unset> is written as the literal @unset.
readonly CASES=(
  "unset-unset|@unset|@unset|boots:production"
  "new-name-development|development|@unset|boots:development"
  "new-name-production|production|@unset|boots:production"
  "old-name-old-vocabulary-alone|@unset|development|refuses:both-names"
  "old-name-old-vocabulary-production-alone|@unset|production|refuses:both-names"
  "both-set-old-vocabulary|production|development|refuses:both-names"
  "both-set-old-vocabulary-dev|development|production|refuses:both-names"
  "old-name-topology-plus-new-name|development|managed|boots:development"
  "old-name-topology-alone|@unset|off|boots:production"
  "old-name-topology-external|production|external|boots:production"
  "garbage-new-name|banana|@unset|refuses:new-name"
  "garbage-old-name|@unset|banana|refuses:old-name"
  "garbage-both|banana|banana|refuses:both-names"
)

FAILURES=0
PASSES=0

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

# run_case NAME MODE TOPOLOGY EXPECT
run_case() {
  local name="$1" mode="$2" topology="$3" expect="$4"
  local port; port="$(free_port)"
  local env=(env "SEARCH_HMAC_KEY=${KEY}" "VIZRA_SEARCH_ADDR=127.0.0.1:${port}")
  [[ "$mode"     != "@unset" ]] && env+=("${ENV_MODE}=${mode}")
  [[ "$topology" != "@unset" ]] && env+=("${ENV_TOPOLOGY}=${topology}")

  local shown_mode="${mode/@unset/<unset>}" shown_topology="${topology/@unset/<unset>}"
  echo
  echo "=== ${name}"
  echo "    ${ENV_MODE}=${shown_mode}  ${ENV_TOPOLOGY}=${shown_topology}  → expect ${expect}"

  local log="${WORK}/${name}.log" code=0
  local want_boot="no"
  [[ "${expect}" == boots:* ]] && want_boot="yes"

  if [[ "${want_boot}" == "yes" ]]; then
    "${env[@]}" "${BIN}" >"${log}" 2>&1 &
    local pid=$!
    local healthy="no"
    for _ in $(seq 1 50); do
      if curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then healthy="yes"; break; fi
      if ! kill -0 "${pid}" 2>/dev/null; then break; fi
      sleep 0.2
    done
    kill -TERM "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
    if [[ "${healthy}" != "yes" ]]; then
      echo "    FAIL: it never became healthy"; sed 's/^/      | /' "${log}"; FAILURES=$((FAILURES+1)); return
    fi
    local want_mode="${expect#boots:}"
    local saw_dev_warning="no"
    grep -q "running in development mode" "${log}" && saw_dev_warning="yes"
    if [[ "${want_mode}" == "development" && "${saw_dev_warning}" != "yes" ]]; then
      echo "    FAIL: booted, but not in development mode (no development warning)"; sed 's/^/      | /' "${log}"; FAILURES=$((FAILURES+1)); return
    fi
    if [[ "${want_mode}" == "production" && "${saw_dev_warning}" == "yes" ]]; then
      echo "    FAIL: booted in DEVELOPMENT mode; production is the default"; sed 's/^/      | /' "${log}"; FAILURES=$((FAILURES+1)); return
    fi
    echo "    ok: healthy on 127.0.0.1:${port}, mode ${want_mode}, then drained on SIGTERM"
    PASSES=$((PASSES+1))
    return
  fi

  # A refusal case must EXIT. Under a mutation it may instead serve forever, so
  # the wait is bounded by a watchdog: a process still alive after REFUSAL_GRACE
  # seconds is killed and reported as having booted. Exit 137 is that kill.
  code=0
  (
    "${env[@]}" "${BIN}" >"${log}" 2>&1 &
    child=$!
    ( sleep "${REFUSAL_GRACE}"; kill -9 "${child}" 2>/dev/null ) &
    watchdog=$!
    wait "${child}"; rc=$?
    kill "${watchdog}" 2>/dev/null || true
    exit "${rc}"
  ) || code=$?
  if [[ "${code}" -eq 0 ]]; then
    echo "    FAIL: the process booted (exit 0) where a refusal was required"; sed 's/^/      | /' "${log}"; FAILURES=$((FAILURES+1)); return
  fi
  if [[ "${code}" -eq 137 ]]; then
    echo "    FAIL: still running after ${REFUSAL_GRACE}s where a refusal was required — it booted"
    sed 's/^/      | /' "${log}"; FAILURES=$((FAILURES+1)); return
  fi
  local want_names="${expect#refuses:}"
  local missing=""
  case "${want_names}" in
    both-names) grep -q "${ENV_TOPOLOGY}" "${log}" || missing+=" ${ENV_TOPOLOGY}"
                grep -q "${ENV_MODE}"     "${log}" || missing+=" ${ENV_MODE}" ;;
    old-name)   grep -q "${ENV_TOPOLOGY}" "${log}" || missing+=" ${ENV_TOPOLOGY}" ;;
    new-name)   grep -q "${ENV_MODE}"     "${log}" || missing+=" ${ENV_MODE}" ;;
  esac
  if [[ -n "${missing}" ]]; then
    echo "    FAIL: refused (exit ${code}) but the message names neither${missing}"; sed 's/^/      | /' "${log}"; FAILURES=$((FAILURES+1)); return
  fi
  if grep -q "${KEY}" "${log}"; then
    echo "    FAIL: the refusal echoed the shared secret"; FAILURES=$((FAILURES+1)); return
  fi
  echo "    ok: refused with exit ${code}, naming${want_names:+ }${want_names//-/ }"
  sed 's/^/      | /' "${log}"
  PASSES=$((PASSES+1))
}

# --------------------------------------------------------------------- main --

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mutate) MUTATION="${2:-}"; shift 2 ;;
    --list-mutations)
      for m in $(mutation_names); do printf '  %-26s %s\n' "$m" "$(mutation_describes "$m")"; done
      exit 0 ;;
    -h|--help) sed -n '2,25p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) die "unknown argument $1" ;;
  esac
done

command -v go      >/dev/null 2>&1 || die "go is not on PATH"
command -v curl    >/dev/null 2>&1 || die "curl is not on PATH"
command -v python3 >/dev/null 2>&1 || die "python3 is not on PATH"
command -v openssl >/dev/null 2>&1 || die "openssl is not on PATH"

WORK="$(mktemp -d)"
BIN="${WORK}/vizra-search"
# Never a literal: production refuses every key this repository publishes, so
# the matrix mints one exactly as an operator is told to.
KEY="$(openssl rand -hex 32)"

echo "boot-matrix: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "repo        $(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown) on $(git -C "${REPO_ROOT}" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
echo "go          $(go version)"
echo "host        $(uname -sm)"
echo "source      internal/config/config.go sha256 $(digest "${TARGET}")"

if [[ -n "${MUTATION}" ]]; then
  mutation_describes "${MUTATION}" >/dev/null || die "unknown mutation ${MUTATION}; try --list-mutations"
  BACKUP="${WORK}/config.go.orig"
  cp "${TARGET}" "${BACKUP}"
  before="$(digest "${TARGET}")"
  apply_mutation "${MUTATION}" || die "mutation ${MUTATION} could not be applied"
  after="$(digest "${TARGET}")"
  if [[ "${before}" == "${after}" ]]; then
    die "mutation ${MUTATION} left the file byte-identical — refusing to report a demonstration that did not happen"
  fi
  echo
  echo "MUTATION    ${MUTATION}"
  echo "            $(mutation_describes "${MUTATION}")"
  echo "            config.go sha256 before ${before}"
  echo "            config.go sha256 after  ${after}"
  echo "            this run MUST go red; a green run means the control is gone"
fi

echo
echo "--- building the binary under test"
( cd "${REPO_ROOT}" && go build -o "${BIN}" ./cmd/vizra-search ) || die "the binary did not build"

# The matrix proves behaviour; the suite names the control that broke. A
# mutation has to turn BOTH red, so the transcript carries the failing test
# names next to the failing boot cases.
echo
echo "=== go-tests (internal/config, cmd/vizra-search)"
if ( cd "${REPO_ROOT}" && go test -count=1 ./internal/config/ ./cmd/vizra-search/ ) >"${WORK}/go-test.log" 2>&1; then
  echo "    ok: the suite passes"
  PASSES=$((PASSES+1))
else
  echo "    FAIL: the suite is red"
  grep -E '^(--- )?(FAIL|\s+--- FAIL)|^\s+config_test|^\s+main_test' "${WORK}/go-test.log" | sed 's/^/      | /' | head -40
  FAILURES=$((FAILURES+1))
fi

for spec in "${CASES[@]}"; do
  IFS='|' read -r name mode topology expect <<<"${spec}"
  run_case "${name}" "${mode}" "${topology}" "${expect}"
done

echo
echo "--- ${PASSES} passed, ${FAILURES} failed, $(( PASSES + FAILURES )) checks (13 boot cases + the focused suite)"
if [[ -n "${MUTATION}" ]]; then
  if [[ "${FAILURES}" -eq 0 ]]; then
    echo "RESULT: GREEN UNDER MUTATION ${MUTATION} — the control does not hold"
    exit 1
  fi
  echo "RESULT: red under mutation ${MUTATION}, as required"
  exit 0
fi
if [[ "${FAILURES}" -ne 0 ]]; then
  echo "RESULT: FAIL"
  exit 1
fi
echo "RESULT: pass"
