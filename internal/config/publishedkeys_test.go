package config_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/yegamble/vizra-search/internal/config"
)

const vendoredVectorsPath = "../../api/search-hmac-testvectors.json"

func vectorsKey(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(vendoredVectorsPath)
	if err != nil {
		t.Fatalf("reading the vendored conformance vectors: %v", err)
	}
	var vf struct {
		KeyUTF8 string `json:"key_utf8"`
	}
	if err := json.Unmarshal(raw, &vf); err != nil {
		t.Fatalf("%s is not JSON: %v", vendoredVectorsPath, err)
	}
	if vf.KeyUTF8 == "" {
		t.Fatalf("%s declares no key_utf8", vendoredVectorsPath)
	}
	return vf.KeyUTF8
}

// TestTheVectorsPublishedKeyIsStillTheOneWeRefuse reads key_utf8 out of the
// vendored file AT TEST TIME rather than duplicating the literal, so
// re-vendoring a changed vectors file cannot silently un-refuse the key.
func TestTheVectorsPublishedKeyIsStillTheOneWeRefuse(t *testing.T) {
	key := vectorsKey(t)
	if key != config.VectorsHMACKey {
		t.Fatalf("the vendored vectors publish a key this loader does not refuse.\n"+
			"  vectors key_utf8 : %d bytes, %d distinct\n"+
			"  config.VectorsHMACKey : %d bytes\n"+
			"Update config.VectorsHMACKey to the vendored value. Neither value is printed here.",
			len(key), len(uniqueBytes(key)), len(config.VectorsHMACKey))
	}
	if !config.IsPublishedKey(key) {
		t.Fatal("the vectors' published key is not in the refused set")
	}
}

// TestProductionRefusesThePublishedVectorsKey is the point of all of it: that
// key is exactly 32 bytes of mixed-case alphanumerics with 32 distinct byte
// values, so every heuristic in the loader accepts it — and it is the one key
// whose documentation is a committed file an operator will read and copy.
func TestProductionRefusesThePublishedVectorsKey(t *testing.T) {
	key := vectorsKey(t)

	// It really does pass every heuristic; this is why the exact-value rule
	// exists rather than a broader rule.
	if len(key) < config.MinProductionKeyBytes {
		t.Fatalf("fixture assumption broken: the vectors key is %d bytes", len(key))
	}
	if len(uniqueBytes(key)) < 8 {
		t.Fatal("fixture assumption broken: the vectors key has few distinct bytes")
	}

	_, err := config.LoadFrom(lookupFrom(map[string]string{
		config.EnvMode:    "production",
		config.EnvHMACKey: key,
	}))
	if err == nil {
		t.Fatal("production ACCEPTED the key published in the conformance vectors")
	}
	if !strings.Contains(err.Error(), config.EnvHMACKey) {
		t.Errorf("the refusal does not name the variable: %s", err.Error())
	}
	if strings.Contains(err.Error(), key) {
		t.Errorf("the refusal echoes the key value")
	}
}

func TestDevelopmentStillAcceptsThePublishedKeys(t *testing.T) {
	// Development is where these keys are meant to be used: the vectors have to
	// be runnable, and `make run` boots with the dev key.
	for _, key := range config.PublishedKeys() {
		cfg, err := config.LoadFrom(lookupFrom(map[string]string{
			config.EnvMode:    "development",
			config.EnvHMACKey: key,
		}))
		if err != nil {
			t.Errorf("development refused a published key: %v", err)
			continue
		}
		if string(cfg.HMACKey) != key {
			t.Error("development did not carry the key through")
		}
	}
}

func TestProductionRefusesEveryPublishedKey(t *testing.T) {
	for _, key := range config.PublishedKeys() {
		_, err := config.LoadFrom(lookupFrom(map[string]string{
			config.EnvMode:    "production",
			config.EnvHMACKey: key,
		}))
		if err == nil {
			t.Error("production accepted a published key")
		}
		if err != nil && strings.Contains(err.Error(), key) {
			t.Error("the refusal echoes the key value")
		}
	}
}

// CheckEnv must report the same refusal, so doctor and CI agree with boot.
func TestCheckEnvRefusesThePublishedVectorsKey(t *testing.T) {
	if err := config.CheckEnv(map[string]string{
		config.EnvMode:    "production",
		config.EnvHMACKey: vectorsKey(t),
	}); err == nil {
		t.Fatal("CheckEnv accepted a production env carrying the vectors' published key")
	}
	if err := config.CheckEnv(map[string]string{
		config.EnvMode:    "development",
		config.EnvHMACKey: vectorsKey(t),
	}); err != nil {
		t.Fatalf("CheckEnv refused the vectors key in development, where it must work: %v", err)
	}
}

// TestEveryKeyLiteralInThisRepositoryIsRefused parses every _test.go file in
// the repository and requires that any string literal bound to a key-shaped
// identifier is refused in production. Without it the refused list would rot
// the first time someone added a new test key.
func TestEveryKeyLiteralInThisRepositoryIsRefused(t *testing.T) {
	root := "../.."
	var found int

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if name := info.Name(); name == ".git" || name == "bin" || name == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}

		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}

		ast.Inspect(file, func(n ast.Node) bool {
			names, values := declaredNamesAndValues(n)
			for i, name := range names {
				if i >= len(values) || !looksLikeAKeyIdentifier(name) {
					continue
				}
				literal, ok := stringLiteral(values[i])
				if !ok || len(literal) < config.MinProductionKeyBytes {
					continue
				}
				found++
				if !config.IsPublishedKey(literal) {
					t.Errorf("%s: %q is a key literal committed to this repository but production would ACCEPT it.\n"+
						"  A committed key is a published key. Add it to config.publishedTestKeys, or generate the key at test time.",
						fset.Position(n.Pos()), name)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the repository: %v", err)
	}
	if found == 0 {
		t.Fatal("this scan found no key literals at all; it is no longer checking anything")
	}
	t.Logf("scanned %d key literals in _test.go sources; every one is refused in production", found)
}

// declaredNamesAndValues extracts the names and values of a const/var
// declaration or a short assignment.
func declaredNamesAndValues(n ast.Node) ([]string, []ast.Expr) {
	switch d := n.(type) {
	case *ast.ValueSpec:
		names := make([]string, 0, len(d.Names))
		for _, ident := range d.Names {
			names = append(names, ident.Name)
		}
		return names, d.Values
	case *ast.AssignStmt:
		names := make([]string, 0, len(d.Lhs))
		for _, lhs := range d.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok {
				names = append(names, ident.Name)
				continue
			}
			names = append(names, "")
		}
		return names, d.Rhs
	}
	return nil, nil
}

// looksLikeAKeyIdentifier matches the names a shared secret is bound to.
func looksLikeAKeyIdentifier(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range []string{"key", "keys", "secret"} {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

// stringLiteral unwraps a plain string literal, including []byte("…").
func stringLiteral(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.CallExpr:
		// []byte("…")
		if len(v.Args) == 1 {
			return stringLiteral(v.Args[0])
		}
	}
	return "", false
}

func uniqueBytes(s string) map[byte]struct{} {
	out := map[byte]struct{}{}
	for i := 0; i < len(s); i++ {
		out[s[i]] = struct{}{}
	}
	return out
}
