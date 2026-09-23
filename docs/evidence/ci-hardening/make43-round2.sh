#!/bin/bash
# Round 2 inside ubuntu:24.04: the remake probe, the single gate, R-2/R-3. /src is a read-only copy.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq make python3 python3-yaml git golang-go >/dev/null 2>&1 || { echo "apt failed"; exit 2; }
echo "### environment"; make --version | head -1; python3 --version; go version
work=$(mktemp -d); cp -a /src/. $work/; cd $work; unset MAKEFLAGS MAKELEVEL GOFLAGS
sha() { sha256sum "$1" | cut -c1-16; }
orig=$(sha Makefile)
A="python3 scripts/make-integrity-guard.py --workflow"
row() { # id desc expect cmd...
  local id="$1" desc="$2" exp="$3"; shift 3
  out=$("$@" 2>&1); rc=$?
  v=$([ $rc -ne 0 ] && echo RED || echo GREEN)
  ok=$([ "$exp" = any ] && echo measured || { [ "$v" = "$exp" ] && echo "ok" || echo "*** UNEXPECTED"; })
  mk=$(sha Makefile)
  line=$(printf '%s\n' "$out" | grep -E 'FAIL|REFUSED|passed|contract-drift lane:' | head -1 | cut -c1-150)
  printf '%-4s %-60s exit %-2s %-5s %-9s Makefile %s%s | %s\n' "$id" "$desc" "$rc" "$v" "$ok" "$mk" "$([ "$mk" = "$orig" ] && echo ' (unchanged)' || echo ' *** CHANGED')" "$line"
}
sib() { mkdir -p "$(dirname "$1")"; { cat Makefile; echo "# sibling bytes nobody pinned"; } > "$1"; touch -d '+1 day' "$1"; }
clear_sib() { rm -rf Makefile.sh Makefile.c Makefile.o Makefile.y Makefile.l Makefile,v RCS SCCS s.Makefile GNUmakefile GNUMakefile Makefile.real; }
echo; echo "### control"
row c0 "clean tree: anchor" GREEN $A
row c1 "clean tree: contract-drift-guard recipe" GREEN python3 scripts/contract-drift-guard.py recipe
row c2 "clean tree: makegate -- --dry-run contract-drift" GREEN python3 scripts/makegate.py -- --dry-run --no-print-directory contract-drift
echo; echo "### a newer sibling make could turn into the Makefile (Makefile sha256 before: $orig)"
for s in Makefile.sh Makefile.c Makefile.o Makefile.y Makefile.l SCCS/s.Makefile s.Makefile Makefile,v RCS/Makefile,v RCS/Makefile; do
  sib "$s"; exp=RED; case "$s" in *,v|RCS/*) exp=any;; esac
  row s "newer $s: anchor" $exp $A
  row s "newer $s: contract-drift-guard recipe" $exp python3 scripts/contract-drift-guard.py recipe
  clear_sib
done
echo; echo "### (the round-1 hole itself is not re-run here: with the probe removed, a +1-day sibling makes make remake"
echo "###  the Makefile, re-exec, find it still older than the sibling, and loop — measured as a hang on the first attempt)"
row c3 "restored" GREEN $A
echo; echo "### R-2 / R-3"
row r1 "MAKEFILES=/dev/null: anchor" RED env MAKEFILES=/dev/null $A
row r2 "MAKEFILES=/dev/null: makegate" RED env MAKEFILES=/dev/null python3 scripts/makegate.py -- --dry-run contract-drift
mkdir -p /tmp/stub; printf '#!/bin/sh\nexec /usr/bin/make "$@"\n' > /tmp/stub/make; chmod +x /tmp/stub/make
row r3 "stub make first on PATH: anchor" RED env PATH=/tmp/stub:$PATH $A
mv Makefile Makefile.real; ln -s Makefile.real Makefile; row r4 "Makefile is a symlink to identical bytes: anchor" RED $A
row r5 "Makefile is a symlink: ci-required-guard.py" RED python3 scripts/ci-required-guard.py; rm Makefile; mv Makefile.real Makefile
printf 'ci:\n\t@true\n' > GNUmakefile; row r6 "unpinned GNUmakefile: ci-required-guard.py" RED python3 scripts/ci-required-guard.py; clear_sib
printf 'ci:\n\t@true\n' > makefile; row r7 "unpinned lowercase makefile (Linux): anchor" RED $A; rm -f makefile
row r8 "BASH_ENV=/dev/null: anchor (must start 0 make processes)" RED env BASH_ENV=/dev/null $A
echo "     anchor line: $(env BASH_ENV=/dev/null $A 2>&1 | grep -o 'make was NOT invoked ([0-9]* make process(es) started)')"
echo '  stale.mk: 0000000000000000000000000000000000000000000000000000000000000000' >> .github/pinned-makefiles.yml
row r9 "a pin entry for a missing file: ci-required-guard.py" RED python3 scripts/ci-required-guard.py
row r10 "the same: anchor" RED $A
cp /src/.github/pinned-makefiles.yml .github/pinned-makefiles.yml
echo; echo "### a pinned INCLUDE with a newer sibling (chair correction: ONE -q naming every pinned file)"
cp Makefile /tmp/M.orig; cp .github/pinned-makefiles.yml /tmp/P.orig
sed -i 's|^.SHELLFLAGS := -eu -o pipefail -c$|&\ninclude inc.mk|' Makefile; echo 'INCLUDED_BY_REVIEW := 1' > inc.mk
python3 - <<'PY'
import hashlib,re
p='.github/pinned-makefiles.yml'; s=open(p).read()
d=hashlib.sha256(open('Makefile','rb').read()).hexdigest(); i=hashlib.sha256(open('inc.mk','rb').read()).hexdigest()
s=re.sub(r'^  Makefile: [0-9a-f]{64}$','  Makefile: '+d,s,flags=re.M)+'  inc.mk: '+i+'\n'; open(p,'w').write(s)
PY
row i0 "Makefile + pinned include, re-pinned: anchor" GREEN $A
inc=$(sha inc.mk); cp inc.mk inc.mk.sh; echo '# sibling bytes nobody pinned' >> inc.mk.sh; touch -d '+2 day' inc.mk.sh
row i1 "newer inc.mk.sh beside the pinned include: anchor" RED $A
echo "     inc.mk sha256 before $inc, after $(sha inc.mk)"
echo "     MEASURED, not the design: a per-file probe \`make -q Makefile\` alone:"
( timeout 60 make -q Makefile >/dev/null 2>&1; echo "       exit $? (124 = still running after 60 s, killed); inc.mk sha256 now $(sha inc.mk)" )
cp /tmp/M.orig Makefile; cp /tmp/P.orig .github/pinned-makefiles.yml; rm -f inc.mk inc.mk.sh
echo; echo "### reviewed (re-pinned) .RECIPEPREFIX / .SECONDEXPANSION: refused before make"
cp Makefile /tmp/M2.orig; cp .github/pinned-makefiles.yml /tmp/P2.orig
repin() { python3 - <<'PY'
import hashlib,re
p='.github/pinned-makefiles.yml'; s=open(p).read()
d=hashlib.sha256(open('Makefile','rb').read()).hexdigest()
open(p,'w').write(re.sub(r'^  Makefile: [0-9a-f]{64}$','  Makefile: '+d,s,flags=re.M))
PY
}
printf '\n.RECIPEPREFIX := >\nextra-target:\n> -true\n' >> Makefile; repin
row x1 ".RECIPEPREFIX := > + '> -true', re-pinned: anchor" RED $A
echo "     anchor line: $($A 2>&1 | grep -o 'make was NOT invoked ([0-9]* make process(es) started)')"
cp /tmp/M2.orig Makefile; cp /tmp/P2.orig .github/pinned-makefiles.yml
printf '\n.SECONDEXPANSION:\n' >> Makefile; repin
row x2 ".SECONDEXPANSION:, re-pinned: anchor" RED $A
echo "     anchor line: $($A 2>&1 | grep -o 'make was NOT invoked ([0-9]* make process(es) started)')"
cp /tmp/M2.orig Makefile; cp /tmp/P2.orig .github/pinned-makefiles.yml
for add in '.IGNORE:' '.DEFAULT: ; @true' '.EXTRA_PREREQS := nothing' 'test: MAKEFLAGS += -i' '%: SHELL := /usr/bin/true' 'inert-target:\n\t+@true'; do
  printf "\n$add\n" >> Makefile; repin
  row x3 "re-pinned: $(printf "$add" | head -1)" RED $A
  echo "     anchor line: $($A 2>&1 | grep -o 'make was NOT invoked ([0-9]* make process(es) started)')"
  cp /tmp/M2.orig Makefile; cp /tmp/P2.orig .github/pinned-makefiles.yml
done
row c4 "clean tree again: anchor" GREEN $A
