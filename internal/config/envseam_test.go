package config_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// processEnvReaders are the standard-library functions that read the process
// environment. Only the Lookup seam may call one.
var processEnvReaders = map[string]map[string]bool{
	"os":                    {"Getenv": true, "LookupEnv": true, "Environ": true, "ExpandEnv": true},
	"syscall":               {"Getenv": true, "Environ": true},
	"golang.org/x/sys/unix": {"Getenv": true, "Environ": true},
}

// The ONE permitted read: internal/config/env.go, function osLookupEnv, calling
// os.LookupEnv exactly once.
const (
	seamFile = "internal/config/env.go"
	seamFunc = "osLookupEnv"
	seamCall = "os.LookupEnv"
)

// TestNothingOutsideTheSeamReadsTheProcessEnvironment makes env.go's comment —
// "osLookupEnv is the only place this package touches the process environment" —
// a control rather than a claim, and widens it to the whole module.
//
// Every refusal, ceiling and no-echo property of the loader is tested through an
// INJECTED Lookup. A direct os.Getenv anywhere else reaches around all of them:
// PR#4's verifier logged an ignored value through os.Getenv in Config.String()
// and every lane stayed green, because the tests inject a map and never see the
// real environment (VERIFY round 2, V3). So this parses every non-test .go file
// in the module and fails on any reference — a call, or taking the function as
// a value — to os.Getenv, os.LookupEnv, os.Environ, os.ExpandEnv,
// syscall.Getenv or syscall.Environ outside osLookupEnv in env.go, under any
// import name. A dot-import of os or syscall is refused outright, because it
// would let `Getenv(...)` be called with no package name to see.
//
// Not seen: reflection, cgo, and reading /proc/self/environ as a file. Review.
func TestNothingOutsideTheSeamReadsTheProcessEnvironment(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root %s has no go.mod: %v", root, err)
	}

	fset := token.NewFileSet()
	seamHits := 0
	scanned := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "vendor", "bin", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Errorf("parsing %s: %v", rel, err)
			return nil
		}
		scanned++

		names := map[string]string{}
		for _, imp := range file.Imports {
			p, err := strconv.Unquote(imp.Path.Value)
			if err != nil || processEnvReaders[p] == nil {
				continue
			}
			name := p[strings.LastIndex(p, "/")+1:]
			if imp.Name != nil {
				name = imp.Name.Name
			}
			if name == "." {
				t.Errorf("%s dot-imports %q, which hides every environment read from this guard", rel, p)
				continue
			}
			names[name] = p
		}

		for _, decl := range file.Decls {
			fnName := ""
			if fn, ok := decl.(*ast.FuncDecl); ok {
				fnName = fn.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				p, ok := names[pkg.Name]
				if !ok || !processEnvReaders[p][sel.Sel.Name] {
					return true
				}
				ref := p + "." + sel.Sel.Name
				if rel == seamFile && fnName == seamFunc && ref == seamCall {
					seamHits++
					return true
				}
				t.Errorf("%s: %s reads the process environment outside the Lookup seam (%s, func %s). "+
					"Take configuration through config.Lookup so the refusals, ceilings and no-echo "+
					"tests see it.", fset.Position(sel.Pos()), ref, seamFile, seamFunc)
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 5 {
		t.Fatalf("only %d non-test Go file(s) scanned under %s; the walk is not reading the module", scanned, root)
	}
	if seamHits != 1 {
		t.Fatalf("the seam %s in %s is referenced %d time(s), want exactly 1: the seam itself moved or was "+
			"duplicated, so this guard no longer knows what it protects", seamCall, seamFile, seamHits)
	}
	t.Logf("scanned %d non-test Go files; the only process-environment read is %s in %s", scanned, seamCall, seamFile)
}
