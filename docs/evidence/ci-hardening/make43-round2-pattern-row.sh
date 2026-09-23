#!/bin/bash
# Supplement to make43-round2.txt: the pattern-specific SHELL row, whose first attempt was lost to a
# harness bug (printf read the `%` as a format). Inside ubuntu:24.04; /src read-only.
set -u
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null && apt-get install -y -qq make python3 git golang-go >/dev/null 2>&1 || { echo "apt failed"; exit 2; }
make --version | head -1
work=$(mktemp -d); cp -a /src/. $work/; cd $work; unset MAKEFLAGS MAKELEVEL GOFLAGS
before=$(sha256sum Makefile | cut -c1-16)
printf '\n%s\n' '%: SHELL := /usr/bin/true' >> Makefile
python3 - <<'PY'
import hashlib,re
p='.github/pinned-makefiles.yml'; s=open(p).read()
d=hashlib.sha256(open('Makefile','rb').read()).hexdigest()
open(p,'w').write(re.sub(r'^  Makefile: [0-9a-f]{64}$','  Makefile: '+d,s,flags=re.M))
PY
echo "Makefile sha256 $before -> $(sha256sum Makefile | cut -c1-16) (re-pinned); last line: $(tail -1 Makefile)"
out=$(python3 scripts/make-integrity-guard.py --workflow 2>&1); rc=$?
echo "anchor exit $rc"; printf '%s\n' "$out" | grep -E 'FAIL|make was NOT invoked' | head -3
