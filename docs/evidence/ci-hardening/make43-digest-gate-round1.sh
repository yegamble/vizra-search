#!/bin/bash
# Round 1 (digest gate), inside ubuntu:24.04. /src is a read-only copy of the branch tree.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq make python3 git golang-go >/dev/null 2>&1 || { echo "apt failed"; exit 2; }
echo "### environment"; make --version | head -1; python3 --version; go version
work=$(mktemp -d); cp -a /src/. $work/; cd $work; unset MAKEFLAGS MAKELEVEL GOFLAGS
A="python3 scripts/make-integrity-guard.py --workflow"
sha() { sha256sum "$1" | cut -c1-16; }
PIN=.github/pinned-makefiles.yml
cp Makefile /tmp/M.orig; cp $PIN /tmp/P.orig; orig=$(sha Makefile)
row() { # id desc expect -- then env file check
  local id="$1" desc="$2" exp="$3"
  : > /tmp/genv
  out=$(env GITHUB_ENV=/tmp/genv $A 2>&1); rc=$?
  v=$([ $rc -ne 0 ] && echo RED || echo GREEN)
  inv=$(printf '%s' "$out" | grep -q "make was NOT invoked" && echo "make NOT invoked" || echo "make invoked")
  line=$(printf '%s\n' "$out" | grep -E '^\s*FAIL|passed' | head -1 | cut -c1-170)
  printf '%-4s %-58s Makefile %s  exit %s %-5s %s  %s | env file:[%s] | %s\n' "$id" "$desc" "$(sha Makefile)" "$rc" "$v" \
    "$([ "$v" = "$exp" ] && echo ok || echo '*** UNEXPECTED')" "$inv" "$(tr '\n' ' ' < /tmp/genv)" "$line"
}
restore() { cp /tmp/M.orig Makefile; cp /tmp/P.orig $PIN; rm -f inc.mk GNUmakefile; [ "$(sha Makefile)" = "$orig" ] && echo "     restored byte-identical ($orig)" || echo "     *** NOT identical"; }
repin() { python3 - <<'PY'
import hashlib,re
d=hashlib.sha256(open('Makefile','rb').read()).hexdigest()
p='.github/pinned-makefiles.yml'; s=open(p).read()
s=re.sub(r'^Makefile: [0-9a-f]{64}$', 'Makefile: '+d, s, flags=re.M); open(p,'w').write(s)
PY
}
FP='.SHELLFLAGS := -eu -o pipefail -c'
echo; echo "### the digest gate (Makefile sha256 before: $orig)"
row c0 "clean Makefile" GREEN
sed -i 's|^SHELL := /bin/bash$|SHELL := /bin/bash |' Makefile; row d1 "one byte changed" RED; restore
sed -i "s|^$FP\$|$FP\ninclude inc.mk|" Makefile; echo 'X := 1' > inc.mk; row d2 "an include line + included file (not re-pinned)" RED; restore
sed -i "s|^$FP\$|$FP\ninclude inc.mk|" Makefile; echo 'X := 1' > inc.mk; repin; row d3 "an included file, Makefile re-pinned (MAKEFILE_LIST)" RED; restore
sed -i "s|^$FP\$|$FP\n.SECONDEXPANSION:|" Makefile; row d4 ".SECONDEXPANSION line (desk review 1)" RED; restore
echo '.RECIPEPREFIX := >' >> Makefile; row d5 ".RECIPEPREFIX line (desk review 2)" RED; restore
printf 'ci:\n\t@true\n' > GNUmakefile; row d6 "an unpinned GNUmakefile beside it" RED; restore
row c1 "clean Makefile again" GREEN
echo; echo "### reviewed bytes (Makefile edited AND re-pinned, as a reviewer would): the readings after make still refuse known shapes"
sed -i "s|^$FP\$|$FP\nMAKEFLAGS += -i|" Makefile; repin; row r1 "MAKEFLAGS += -i, re-pinned" RED; restore
sed -i "s|^$FP\$|$FP\n.SECONDEXPANSION:|" Makefile; repin; row r2 ".SECONDEXPANSION, re-pinned" RED; restore
echo '.RECIPEPREFIX := >' >> Makefile; repin; row r3 ".RECIPEPREFIX, re-pinned" RED; restore
sed -i 's|^\tgo test -race -count=1 $(PKG)$|\t-go test -race -count=1 $(PKG)|' Makefile; repin; row r4 "- prefix on the test recipe, re-pinned" RED; restore
echo; echo "### environment rows (strict --workflow)"
for kv in "MAKEFLAGS=-i" "MAKELEVEL=1 MAKEFLAGS=-ki" "MAKEFILES=/tmp/x.mk" "BASH_ENV=/tmp/fn.sh" "VERSION=x" "GOFLAGS=-run=^\$"; do
  out=$(env $kv $A 2>&1); rc=$?; printf '  env %-28s exit %s  %s\n' "$kv" "$rc" "$(printf '%s\n' "$out" | grep FAIL | head -1 | cut -c1-120)"
done
