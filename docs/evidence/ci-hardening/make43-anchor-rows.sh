#!/bin/bash
# Runs inside ubuntu:24.04. /src is a read-only copy of the branch tree.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq make python3 python3-yaml git golang-go >/dev/null 2>&1 || { echo "apt failed"; exit 2; }
echo "### environment"; make --version | head -1; python3 --version; go version; uname -m
work=$(mktemp -d); cp -a /src/. $work/; cd $work
unset MAKEFLAGS MAKELEVEL GOFLAGS
sha() { sha256sum "$1" | cut -c1-12; }
row() { # id, description, expected (red|green), command...
  local id="$1" desc="$2" exp="$3"; shift 3
  out=$("$@" 2>&1); rc=$?
  verdict=$([ $rc -ne 0 ] && echo RED || echo GREEN)
  line=$(printf '%s\n' "$out" | grep -E '^\s*FAIL|passed|FAILED' | head -1 | cut -c1-200)
  ok=$([ "$exp" = measured ] && echo "measured" || { [ "$verdict" = "$(echo $exp | tr a-z A-Z)" ] && echo "ok (expected $exp)" || echo "*** UNEXPECTED"; })
  printf '%-4s %-62s exit %-3s %-5s %s | %s\n' "$id" "$desc" "$rc" "$verdict" "$ok" "$line"
}
mutate() { # file old new  -> applies exactly once or refuses
  python3 - "$1" "$2" "$3" <<'PY'
import sys
p,old,new=sys.argv[1:4]
s=open(p).read()
if old=="":
    s=s+new
else:
    n=s.count(old)
    if n!=1: print(f"REFUSED: {old!r} occurs {n} times"); sys.exit(3)
    s=s.replace(old,new,1)
open(p,'w').write(s)
PY
}
A="python3 scripts/make-integrity-guard.py --workflow"
echo; echo "### control"
row c0 "real Makefile, clean environment" green $A
echo; echo "### the anchor's environment (strict mode is selected by --workflow)"
for kv in "MAKEFLAGS=-i" "MAKEFLAGS=" "GNUMAKEFLAGS=-ki" "MFLAGS=-i" "MAKELEVEL=1 MAKEFLAGS=-ki" "MAKELEVEL= MAKEFLAGS=--ign" "MAKELEVEL=1 MAKEFLAGS=n" "MAKE_RESTARTS=1" "MAKEOVERRIDES=SHELL=/usr/bin/true" "MAKECMDGOALS=ci" "MAKEFILES=/tmp/x.mk" "BASH_ENV=/tmp/fn.sh" "ENV=/tmp/fn.sh" "SHELL=/usr/bin/true" "VERSION=x" "COMMIT=x" "BUILD_TIME=x" "IMAGE=x" "CORE=/tmp/x" "CORE_REMOTE=evil" "GOFLAGS=-run=^\$"; do
  row e "env $kv" red env $kv $A
done
mkdir -p /tmp/stub; printf '#!/bin/sh\nexec /usr/bin/make "$@"\n' > /tmp/stub/make; chmod +x /tmp/stub/make
row e "env PATH=/tmp/stub:\$PATH (a non-system make)" red env PATH=/tmp/stub:$PATH $A
echo; echo "### Makefile mutations (each applied to a fresh copy; digest before -> after)"
orig=$(sha Makefile); cp Makefile /tmp/Makefile.orig
m() { # id desc old new [extra-file name body]
  cp /tmp/Makefile.orig Makefile; rm -f inc.mk gen.mk
  mutate Makefile "$3" "$4" || { echo "$1 REFUSED (did not apply)"; return; }
  [ $# -ge 6 ] && printf '%s' "$6" > "$5"
  echo "     Makefile sha256 $orig -> $(sha Makefile)"
  : > /tmp/genv; ENVF=/tmp/genv
  case "$1" in g*|h*) ENVF=/tmp/_runner_file_commands/set_env_x; : > $ENVF;; esac
  exp=red; case "$1" in p*|g*) exp=green;; n*) exp=measured;; esac   # n/p/g rows REPRODUCE the hole: green is the expected (bad) outcome
  row "$1" "$2" $exp env GITHUB_ENV=$ENVF $A
  echo "     runner env file after the anchor: [$(tr '\n' ' ' < $ENVF)]"
  cp /tmp/Makefile.orig Makefile; rm -f inc.mk gen.mk
  [ "$(sha Makefile)" = "$orig" ] && echo "     restored byte-identical ($orig)" || echo "     *** restore NOT identical"
}
FP='.SHELLFLAGS := -eu -o pipefail -c
'
TR='	go test -race -count=1 $(PKG)
'
m m1 "SHELL := /usr/bin/true" 'SHELL := /bin/bash
' 'SHELL := /usr/bin/true
'
m m2 "MAKEFLAGS += -i" "$FP" "${FP}MAKEFLAGS += -i
"
m m3 "GNUMAKEFLAGS += -i" "$FP" "${FP}GNUMAKEFLAGS += -i
"
m m4 ".SHELLFLAGS := -c" "$FP" '.SHELLFLAGS := -c
'
m m5 ".ONESHELL:" "$FP" "${FP}.ONESHELL:
"
m m6 "- prefix on the test recipe" "$TR" '	-go test -race -count=1 $(PKG)
'
m m7 "|| true on the test recipe" "$TR" '	go test -race -count=1 $(PKG) || true
'
m m8 "duplicate test target" "" '
test:
	@true
'
m m9 "test target inside ifndef" 'test: ## Full test suite with the race detector
'"$TR" 'ifndef VIZRA_NEVER_SET
test: ## Full test suite with the race detector
'"$TR"'endif
'
m m10 "\$(shell) writes \$GITHUB_ENV while being read" "$FP" "${FP}"'POISON := $(shell echo MAKEFLAGS=-i >> "$$GITHUB_ENV")
'
m m11 "a rule that remakes the Makefile" "" '
Makefile: FORCE ; @echo MAKEFLAGS=-i >> "$$GITHUB_ENV"
FORCE:
'
m m12 "include of a remade makefile" "$FP" "${FP}"'include gen.mk
gen.mk: ; @echo MAKEFLAGS=-i >> "$$GITHUB_ENV"; touch gen.mk
'
m m13 "+ recipe line" '	go vet $(PKG)
' '	go vet $(PKG)
	+@echo MAKEFLAGS=-i >> "$$GITHUB_ENV"
'
echo; echo "### MEASURED: the pre-flight removed, the command-file variables still stripped (n rows carry no expectation)"
cp scripts/make-integrity-guard.py /tmp/mig.orig
mutate scripts/make-integrity-guard.py '    if not check_parse_time_side_effects(g, root):
' '    if False and not check_parse_time_side_effects(g, root):
' >/dev/null
m n10 "\$(shell) writes \$GITHUB_ENV (no pre-flight)" "$FP" "${FP}"'POISON := $(shell echo MAKEFLAGS=-i >> "$$GITHUB_ENV")
'
m n11 "a rule that remakes the Makefile (no pre-flight)" "" '
Makefile: FORCE ; @echo MAKEFLAGS=-i >> "$$GITHUB_ENV"
FORCE:
'
m n12 "include of a remade makefile (no pre-flight)" "$FP" "${FP}"'include gen.mk
gen.mk: ; @echo MAKEFLAGS=-i >> "$$GITHUB_ENV"; touch gen.mk
'
echo; echo "### THE HOLE REPRODUCED: the anchor as ported from core (no pre-flight, command-file variables not stripped) — expected GREEN with the env file written"
mutate scripts/make-integrity-guard.py '    drop = {"MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKELEVEL", "BASH_ENV", "ENV", *RUNNER_COMMAND_FILES}
' '    drop = {"MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "MAKELEVEL"}
' >/dev/null
m p10 "\$(shell) writes \$GITHUB_ENV (as ported)" "$FP" "${FP}"'POISON := $(shell echo MAKEFLAGS=-i >> "$$GITHUB_ENV")
'
m p11 "a rule that remakes the Makefile (as ported)" "" '
Makefile: FORCE ; @echo MAKEFLAGS=-i >> "$$GITHUB_ENV"
FORCE:
'
cp /tmp/mig.orig scripts/make-integrity-guard.py
echo; echo "### stripping the variable alone is not enough: a glob finds the runner's file (pre-flight removed, stripping kept)"
mutate scripts/make-integrity-guard.py '    if not check_parse_time_side_effects(g, root):
' '    if False and not check_parse_time_side_effects(g, root):
' >/dev/null
mkdir -p /tmp/_runner_file_commands
m g10 "\$(shell) globs the runner dir (no pre-flight, stripped env)" "$FP" "${FP}"'POISON := $(shell for f in /tmp/_runner_file_commands/set_env_*; do echo MAKEFLAGS=-i >> $$f; done)
'
echo "     /tmp/_runner_file_commands/set_env_x: [$(tr '\n' ' ' < /tmp/_runner_file_commands/set_env_x 2>/dev/null)]"
cp /tmp/mig.orig scripts/make-integrity-guard.py
: > /tmp/_runner_file_commands/set_env_x
m h10 "the same glob, WITH the pre-flight" "$FP" "${FP}"'POISON := $(shell for f in /tmp/_runner_file_commands/set_env_*; do echo MAKEFLAGS=-i >> $$f; done)
'
echo "     /tmp/_runner_file_commands/set_env_x: [$(tr '\n' ' ' < /tmp/_runner_file_commands/set_env_x)]"
echo; echo "### control after restores"
row c1 "real Makefile, clean environment" green $A
echo; echo "### what GNU Make 4.3 does with the workflow-line evasions (a Makefile whose ci recipe is 'exit 7')"
d=$(mktemp -d); printf 'SHELL := /bin/bash\nci:\n\t@echo RECIPE RAN; exit 7\n' > $d/Makefile; cd $d
for cmd in "make ci" "make -i ci" "make -j -i ci" "make -l -i ci" "MAKEFLAGS=-i make ci" "GNUMAKEFLAGS=-i make ci" "M=make; \$M -i ci" "make(){ :; }; make ci" 'echo `make -i ci`' "MAKELEVEL=1 MAKEFLAGS=-ki make ci" "MAKELEVEL=1 MAKEFLAGS=n make ci"; do
  bash -c "$cmd" >/dev/null 2>&1; printf '  %-40s exit=%s\n' "$cmd" "$?"
done
