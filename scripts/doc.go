// Package scripts exists so the Python and shell programs in this directory —
// the ones that decide whether CI can fail — have Go meta-tests that run in the
// ordinary suite, and therefore in the `test` lane (under make) and the
// `test-noskip` lane (without make).
//
// A check whose own correctness nothing pins is a check that quietly stops
// checking. scripts_test.go drives ci-required-guard.py, ci-required-guard.sh,
// make-integrity-guard.py and go-test-report.py against controlled mutations of
// this repository's REAL workflow, manifest, pins and Makefile, and against
// synthetic `go test -json` streams, and asserts that each is refused by name.
//
// There is no Go code here beyond this file.
package scripts
