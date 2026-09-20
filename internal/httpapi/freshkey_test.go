package httpapi_test

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/yegamble/vizra-search/internal/config"
)

// testKey is generated once per test binary rather than committed.
//
// Production refuses every key literal committed to this repository: a
// committed key is a published key. These tests build production-mode servers,
// so their key must be minted the way an operator is told to mint one. A
// literal here would either weaken that refusal or fail the suite.
var testKey = mustFreshKey()

func mustFreshKey() string {
	for {
		var raw [32]byte
		if _, err := rand.Read(raw[:]); err != nil {
			panic("generating a test key: " + err.Error())
		}
		key := hex.EncodeToString(raw[:])
		if !config.IsPublishedKey(key) {
			return key
		}
	}
}
