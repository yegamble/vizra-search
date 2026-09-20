package config_test

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/yegamble/vizra-search/internal/config"
)

// freshKey returns a key generated at test time.
//
// It is deliberately NOT a literal. Production refuses every key literal
// committed to this repository, because a committed key is a published key —
// so a test that needs a production-valid key must mint one, exactly as an
// operator is told to (`openssl rand -hex 32`). Hard-coding one here would
// either weaken the refusal or fail this suite, and both are worse than this.
func freshKey(t *testing.T) string {
	t.Helper()
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	key := hex.EncodeToString(raw[:])
	if config.IsPublishedKey(key) {
		t.Fatalf("a randomly generated key collided with a published one")
	}
	return key
}
