package config_test

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yegamble/vizra-search/internal/config"
)

// envWith builds a candidate environment around a freshly generated key. The
// key is NOT a literal: production refuses every key committed to this
// repository, so a test that needs a production-valid configuration mints one.
func envWith(t *testing.T, overrides map[string]string) map[string]string {
	t.Helper()
	base := map[string]string{
		config.EnvHMACKey: freshKey(t),
	}
	for k, v := range overrides {
		if v == "" {
			delete(base, k)
			continue
		}
		base[k] = v
	}
	return base
}

func lookupFrom(env map[string]string) config.Lookup {
	return func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	}
}

func TestLoadFromDefaultsToProductionWhenModeIsOmitted(t *testing.T) {
	// Fail-secure: an env file that forgets to declare its mode is treated as
	// production, so the production refusals apply (ADR-002, setup.Check
	// precedent).
	cfg, err := config.LoadFrom(lookupFrom(envWith(t, nil)))
	if err != nil {
		t.Fatalf("LoadFrom: unexpected error: %v", err)
	}
	if cfg.Mode != config.ModeProduction {
		t.Fatalf("Mode = %q, want %q", cfg.Mode, config.ModeProduction)
	}
	if cfg.Addr != config.DefaultAddr {
		t.Errorf("Addr = %q, want %q", cfg.Addr, config.DefaultAddr)
	}
	if cfg.MaxClockSkew != config.DefaultMaxClockSkew {
		t.Errorf("MaxClockSkew = %v, want %v", cfg.MaxClockSkew, config.DefaultMaxClockSkew)
	}
	if cfg.MaxBodyBytes != config.DefaultMaxBodyBytes {
		t.Errorf("MaxBodyBytes = %d, want %d", cfg.MaxBodyBytes, config.DefaultMaxBodyBytes)
	}
	if cfg.RequestTimeout != config.DefaultRequestTimeout {
		t.Errorf("RequestTimeout = %v, want %v", cfg.RequestTimeout, config.DefaultRequestTimeout)
	}
}

func TestProductionRefusesUnsafeHMACKeys(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want string
	}{
		// This is the demonstration case D3: the documented development key
		// must never boot a production process.
		{"the documented dev key", config.DevHMACKey, "development placeholder"},
		{"empty", "", "must be set"},
		{"whitespace only", "   ", "must be set"},
		{"short", "abc123", "at least 32 bytes"},
		{"changeme", "changeme-changeme-changeme-changeme", "development placeholder"},
		{"dev prefix", "dev-0123456789abcdef0123456789abcdef", "development placeholder"},
		{"test prefix", "test-0123456789abcdef0123456789abcdef", "development placeholder"},
		{"insecure substring", "0123456789-insecure-0123456789abcdef", "development placeholder"},
		{"repeated byte", strings.Repeat("a", 48), "distinct byte values"},
		// 31 bytes with plenty of variety: only the length rule can catch it,
		// so this case cannot pass by accident through another refusal.
		{"one byte below the floor", "0123456789abcdefghijklmnopqrstu", "at least 32 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := envWith(t, map[string]string{config.EnvMode: "production"})
			if tc.key == "" {
				delete(env, config.EnvHMACKey)
			} else {
				env[config.EnvHMACKey] = tc.key
			}
			_, err := config.LoadFrom(lookupFrom(env))
			if err == nil {
				t.Fatalf("LoadFrom accepted key %q in production mode; it must refuse", tc.key)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err.Error(), tc.want)
			}
			if !errors.Is(err, config.ErrInvalidConfig) {
				t.Fatalf("error %v is not ErrInvalidConfig", err)
			}
		})
	}
}

func TestProductionAcceptsAStrongKey(t *testing.T) {
	env := envWith(t, map[string]string{config.EnvMode: "production"})
	cfg, err := config.LoadFrom(lookupFrom(env))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if string(cfg.HMACKey) != env[config.EnvHMACKey] {
		t.Fatalf("HMACKey not carried through")
	}
	if !cfg.Mode.IsProduction() {
		t.Fatalf("Mode.IsProduction() = false")
	}
}

func TestDevelopmentModeStillRefusesAnEmptyKey(t *testing.T) {
	env := envWith(t, map[string]string{config.EnvMode: "development"})
	delete(env, config.EnvHMACKey)
	if _, err := config.LoadFrom(lookupFrom(env)); err == nil {
		t.Fatal("development mode accepted an empty HMAC key; unauthenticated internal endpoints must be impossible")
	}
}

func TestDevelopmentModeAcceptsTheDevKey(t *testing.T) {
	cfg, err := config.LoadFrom(lookupFrom(envWith(t, map[string]string{
		config.EnvMode:    "development",
		config.EnvHMACKey: config.DevHMACKey,
	})))
	if err != nil {
		t.Fatalf("development mode refused the dev key: %v", err)
	}
	if cfg.Mode.IsProduction() {
		t.Fatal("Mode.IsProduction() = true for development")
	}
}

func TestUnknownModeIsRefused(t *testing.T) {
	_, err := config.LoadFrom(lookupFrom(envWith(t, map[string]string{
		config.EnvMode: "staging",
	})))
	if err == nil {
		t.Fatal("an unrecognised mode must fail closed, not fall back to development")
	}
	if !strings.Contains(err.Error(), config.EnvMode) {
		t.Fatalf("error %q does not name the offending variable", err.Error())
	}
}

// The runtime mode is VIZRA_MODE — the PLATFORM name, the one vizra-core reads
// for the same concept. VIZRA_SEARCH_MODE is core's search TOPOLOGY variable,
// owned and read by core alone; its vocabulary is core's and is deliberately
// not restated in this repository.

func TestTheRuntimeModeIsReadFromVizraMode(t *testing.T) {
	if config.EnvMode != "VIZRA_MODE" {
		t.Fatalf("EnvMode = %q, want %q: one operator-facing name per concept", config.EnvMode, "VIZRA_MODE")
	}
	if config.EnvSearchTopology != "VIZRA_SEARCH_MODE" {
		t.Fatalf("EnvSearchTopology = %q, want %q", config.EnvSearchTopology, "VIZRA_SEARCH_MODE")
	}
	for _, tc := range []struct {
		value string
		want  config.Mode
	}{
		{"development", config.ModeDevelopment},
		{"production", config.ModeProduction},
		{"  Production  ", config.ModeProduction},
	} {
		cfg, err := config.LoadFrom(lookupFrom(envWith(t, map[string]string{config.EnvMode: tc.value})))
		if err != nil {
			t.Fatalf("%s=%q: %v", config.EnvMode, tc.value, err)
		}
		if cfg.Mode != tc.want {
			t.Fatalf("%s=%q gave mode %q, want %q", config.EnvMode, tc.value, cfg.Mode, tc.want)
		}
	}
}

// TestTheOldRuntimeModeNameIsRefusedByName is the rename's central control. The
// old name is NOT read as a mode any more and there is no compatibility alias,
// so a value from the old vocabulary must be refused rather than ignored: an
// operator who carried `VIZRA_SEARCH_MODE=development` forward has a file that
// LOOKS configured while the process picked a mode the file never named.
func TestTheOldRuntimeModeNameIsRefusedByName(t *testing.T) {
	for _, value := range []string{
		"development",
		"production",
		"Development",
		"PRODUCTION",
		"  development  ",
	} {
		t.Run(value, func(t *testing.T) {
			_, err := config.LoadFrom(lookupFrom(envWith(t, map[string]string{
				config.EnvSearchTopology: value,
			})))
			if err == nil {
				t.Fatalf("%s=%q booted; the old runtime vocabulary must be refused by name", config.EnvSearchTopology, value)
			}
			if !errors.Is(err, config.ErrInvalidConfig) {
				t.Fatalf("error %v is not ErrInvalidConfig", err)
			}
			msg := err.Error()
			if !strings.Contains(msg, config.EnvSearchTopology) {
				t.Fatalf("error %q does not name the offending variable", msg)
			}
			if !strings.Contains(msg, config.EnvMode) {
				t.Fatalf("error %q does not name %s as the replacement", msg, config.EnvMode)
			}
		})
	}
}

// The special danger the chair named: an operator with the old name set to the
// old vocabulary and no new name must NOT silently end up in production (with a
// development key they believe is being accepted) or in development. Either
// silent outcome is worse than not booting.
func TestTheOldNameAloneNeverSilentlySelectsAMode(t *testing.T) {
	env := envWith(t, map[string]string{config.EnvSearchTopology: "development"})
	env[config.EnvHMACKey] = config.DevHMACKey
	delete(env, config.EnvMode)

	cfg, err := config.LoadFrom(lookupFrom(env))
	if err == nil {
		t.Fatalf("booted in mode %q instead of refusing", cfg.Mode)
	}
	if !strings.Contains(err.Error(), config.EnvSearchTopology) {
		t.Fatalf("error %q does not name %s", err.Error(), config.EnvSearchTopology)
	}
}

// Refused in EVERY mode, not only in production: unlike a retired secret, the
// wrong name here changes the MODE ITSELF, so development cannot be the mode in
// which the check is skipped.
func TestTheOldRuntimeModeNameIsRefusedInDevelopmentToo(t *testing.T) {
	_, err := config.LoadFrom(lookupFrom(envWith(t, map[string]string{
		config.EnvMode:           "development",
		config.EnvSearchTopology: "development",
	})))
	if err == nil {
		t.Fatal("development mode ignored the old runtime-mode name")
	}
	if !strings.Contains(err.Error(), config.EnvSearchTopology) {
		t.Fatalf("error %q does not name %s", err.Error(), config.EnvSearchTopology)
	}
}

// EVERY value but the old runtime vocabulary is ignored in silence. The
// variable is core's; validating core's vocabulary here would buy no safety and
// would make this service refuse to boot the day core extends it. So core's
// topology values, values this service has never heard of, whitespace-only and
// empty are all the same thing to this loader: nothing.
func TestEveryValueButTheOldVocabularyIsIgnored(t *testing.T) {
	for _, value := range []string{
		// core's topology values, which a shared env file legitimately carries
		"off", "managed", "external",
		// values this service has never heard of, including the ones an
		// operator who meant a mode would reach for
		"staging", "dev", "prod", "developmnt", "1",
		// whitespace-only and empty
		"   ", "",
	} {
		name := value
		if strings.TrimSpace(name) == "" {
			name = "blank" + strconv.Itoa(len(value))
		}
		t.Run(name, func(t *testing.T) {
			cfg, err := config.LoadFrom(lookupFrom(envWith(t, map[string]string{
				config.EnvSearchTopology: value,
			})))
			if err != nil {
				t.Fatalf("%s=%q was refused: %v", config.EnvSearchTopology, value, err)
			}
			if cfg.Mode != config.ModeProduction {
				t.Fatalf("mode = %q, want %q: this variable must not influence the mode", cfg.Mode, config.ModeProduction)
			}

			cfg, err = config.LoadFrom(lookupFrom(envWith(t, map[string]string{
				config.EnvMode:           "development",
				config.EnvSearchTopology: value,
			})))
			if err != nil {
				t.Fatalf("%s=development + %s=%q refused: %v", config.EnvMode, config.EnvSearchTopology, value, err)
			}
			if cfg.Mode != config.ModeDevelopment {
				t.Fatalf("mode = %q, want %q: the new name decides the mode", cfg.Mode, config.ModeDevelopment)
			}
		})
	}
}

// The accepted cost of ignoring what we do not own, stated as a test: a typo in
// the old name can never produce development. It produces PRODUCTION — the
// strict mode — and the operator finds out because the development affordances
// they wanted are refused. Running development without asking for it requires
// an explicit VIZRA_MODE=development and can never come from this variable.
func TestNoValueInTheOldNameCanEverProduceDevelopment(t *testing.T) {
	for _, value := range []string{
		"developmnt", "DEVELOPMENT_", "dev", "development-mode", "off", "managed", "external", "   ", "",
	} {
		env := envWith(t, map[string]string{config.EnvSearchTopology: value})
		// The dev key makes the point sharper: if this value ever selected
		// development, the key would be ACCEPTED and nothing would say so.
		env[config.EnvHMACKey] = config.DevHMACKey
		cfg, err := config.LoadFrom(lookupFrom(env))
		if err == nil {
			t.Fatalf("%s=%q booted in mode %q with the published development key", config.EnvSearchTopology, value, cfg.Mode)
		}
		if !strings.Contains(err.Error(), "development placeholder") {
			t.Fatalf("%s=%q: refusal was %q, not the production key refusal — the mode was not production",
				config.EnvSearchTopology, value, err.Error())
		}
	}
}

// The old name is consulted exactly once, by the refusal. A second lookup is a
// compatibility alias growing back — the thing core's RetiredKeys comment says
// must not exist, because a value that has no effect must be refused, not read.
func TestTheOldNameIsConsultedOnlyByTheRefusal(t *testing.T) {
	env := envWith(t, map[string]string{config.EnvMode: "production"})
	lookups := 0
	_, err := config.LoadFrom(func(key string) (string, bool) {
		if key == config.EnvSearchTopology {
			lookups++
		}
		v, ok := env[key]
		return v, ok
	})
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if lookups != 1 {
		t.Fatalf("%s was looked up %d times, want exactly 1 (the refusal)", config.EnvSearchTopology, lookups)
	}
}

// refusalSite is one `v.addf` call in the loader — one way this process can
// refuse to boot — together with the probes that provoke it and the values
// those probes supply.
//
// The table is exhaustive by construction:
// TestEveryRefusalSiteInTheLoaderHasANoEchoRow parses internal/config/config.go
// and fails unless every `v.addf` call in it is accounted for here, and unless
// every row here matches a call that exists. A refusal added to the loader
// without a row is a red test, which is what makes the sentence "no refusal
// message ever echoes a value" a property of the loader rather than of the
// seven paths someone happened to think of.
type refusalSite struct {
	// format is a fragment of the addf FORMAT STRING, unique among them. It is
	// how the AST guard pairs a row with the call sites it covers.
	format string
	// sites is how many addf calls share that format string. Three of the
	// loader's messages are emitted from more than one place.
	sites int
	// rendered is a fragment of the MESSAGE as the operator sees it, asserted
	// on every probe so a probe cannot silently provoke a different refusal.
	rendered string
	// why documents a value that cannot be an arbitrary marker, and what is
	// asserted instead. Empty means the probe supplies a marker.
	why string
	// probes each build an environment and list the values supplied in it. All
	// of them must be absent from the resulting error.
	probes func(t *testing.T, marker func() string) []refusalProbe
}

type refusalProbe struct {
	env      map[string]string
	supplied []string
}

// one is the common shape: a single variable carrying a single value.
func one(key, value string) []refusalProbe {
	return []refusalProbe{{env: map[string]string{key: value}, supplied: []string{value}}}
}

func refusalSites() []refusalSite {
	return []refusalSite{
		{
			format:   `must be %q or %q`,
			sites:    1,
			rendered: `must be "production" or "development"`,
			probes: func(_ *testing.T, marker func() string) []refusalProbe {
				return one(config.EnvMode, marker())
			},
		},
		{
			format:   `OLD runtime-mode vocabulary`,
			sites:    1,
			rendered: `OLD runtime-mode vocabulary`,
			why: "this site fires only for the retired vocabulary, so its value cannot be an " +
				"arbitrary marker. The SHAPE is the marker instead: an oddly-cased, space-padded " +
				"spelling the message must not reproduce, even though it legitimately prints the " +
				"vocabulary word in its canonical spelling.",
			probes: func(_ *testing.T, _ func() string) []refusalProbe {
				raw := "  DeVeLoPmEnT\t"
				return []refusalProbe{{
					env:      map[string]string{config.EnvSearchTopology: raw},
					supplied: []string{raw, "DeVeLoPmEnT"},
				}}
			},
		},
		{
			format:   `is not a host:port`,
			sites:    1,
			rendered: `is not a host:port listen address`,
			probes: func(_ *testing.T, marker func() string) []refusalProbe {
				return one(config.EnvAddr, marker())
			},
		},
		{
			format:   `is not a duration`,
			sites:    1,
			rendered: `is not a duration`,
			probes: func(_ *testing.T, marker func() string) []refusalProbe {
				// One site, reached through each of the three duration
				// variables, each carrying its own marker.
				skew, timeout, grace := marker(), marker(), marker()
				return []refusalProbe{{
					env: map[string]string{
						config.EnvMaxClockSkew:   skew,
						config.EnvRequestTimeout: timeout,
						config.EnvShutdownGrace:  grace,
					},
					supplied: []string{skew, timeout, grace},
				}}
			},
		},
		{
			format:   `must be greater than zero`,
			sites:    2,
			rendered: `must be greater than zero`,
			why: "both sites fire only for a value that PARSES and is not positive, so the " +
				"supplied value is constrained to that shape rather than free. One site is " +
				"reached through a duration variable and the other through the byte count.",
			probes: func(_ *testing.T, _ func() string) []refusalProbe {
				return []refusalProbe{
					{
						env:      map[string]string{config.EnvRequestTimeout: "-7h6m5s"},
						supplied: []string{"-7h6m5s"},
					},
					{
						env:      map[string]string{config.EnvMaxBodyBytes: "-765432"},
						supplied: []string{"-765432"},
					},
				}
			},
		},
		{
			format:   `is not an integer number of bytes`,
			sites:    1,
			rendered: `is not an integer number of bytes`,
			probes: func(_ *testing.T, marker func() string) []refusalProbe {
				return one(config.EnvMaxBodyBytes, marker())
			},
		},
		{
			format:   `must not exceed %s in %s mode`,
			sites:    1,
			rendered: `must not exceed`,
			why: "the ceiling fires only for a VALID duration above the contract's window, so " +
				"the value must parse; a marker never reaches it.",
			probes: func(_ *testing.T, _ func() string) []refusalProbe {
				return one(config.EnvMaxClockSkew, "3607s")
			},
		},
		{
			format:   `must not exceed %d bytes in %s mode`,
			sites:    1,
			rendered: `must not exceed`,
			why: "the ceiling fires only for a VALID byte count above 8 MiB, so the value must " +
				"parse; a marker never reaches it.",
			probes: func(_ *testing.T, _ func() string) []refusalProbe {
				return one(config.EnvMaxBodyBytes, "16777217")
			},
		},
		{
			format:   `must be set`,
			sites:    1,
			rendered: `must be set`,
			why: "this site fires only when the key is ABSENT or blank, so there is no supplied " +
				"value that could be echoed. The probe supplies whitespace and asserts the " +
				"message names the variable and carries nothing else.",
			probes: func(_ *testing.T, _ func() string) []refusalProbe {
				return []refusalProbe{{
					env:      map[string]string{config.EnvHMACKey: "   "},
					supplied: nil,
				}}
			},
		},
		{
			format:   `is the documented development placeholder`,
			sites:    1,
			rendered: `is the documented development placeholder`,
			why: "fires only for one exact published constant, so the value is that constant. " +
				"It is a key, so its absence from the message matters more here than anywhere.",
			probes: func(_ *testing.T, _ func() string) []refusalProbe {
				return one(config.EnvHMACKey, config.DevHMACKey)
			},
		},
		{
			format:   `is a key published in this repository`,
			sites:    1,
			rendered: `is a key published in this repository`,
			why:      "fires only for an exact published value, so the value is that constant.",
			probes: func(_ *testing.T, _ func() string) []refusalProbe {
				return one(config.EnvHMACKey, config.VectorsHMACKey)
			},
		},
		{
			format:   `looks like a development placeholder`,
			sites:    3,
			rendered: `looks like a development placeholder`,
			why: "three sites — an exact placeholder word, a placeholder PREFIX and a " +
				"placeholder SUBSTRING — share one message. The exact site needs the whole " +
				"value to be a placeholder word; the other two can carry a marker around one, " +
				"and do.",
			probes: func(_ *testing.T, marker func() string) []refusalProbe {
				return []refusalProbe{
					one(config.EnvHMACKey, "devkey")[0],
					one(config.EnvHMACKey, "dev-"+marker()+marker())[0],
					one(config.EnvHMACKey, marker()+"insecure"+marker())[0],
				}
			},
		},
		{
			format:   `must be at least %d bytes in %s mode`,
			sites:    1,
			rendered: `must be at least`,
			probes: func(_ *testing.T, marker func() string) []refusalProbe {
				// Short enough to hit the length floor, and shaped so no
				// placeholder rule catches it first.
				return one(config.EnvHMACKey, marker())
			},
		},
		{
			format:   `must contain at least 8 distinct byte values`,
			sites:    1,
			rendered: `must contain at least 8 distinct byte values`,
			why: "fires only for a key with almost no variety, so the value is a repeated " +
				"character by construction.",
			probes: func(_ *testing.T, _ func() string) []refusalProbe {
				return one(config.EnvHMACKey, strings.Repeat("q", 48))
			},
		},
	}
}

// TestNoRefusalEchoesTheSuppliedValue drives every refusal path in the loader —
// all 17 `v.addf` sites, through the table above — and fails if the value a
// probe supplied comes back in the error, or if an IGNORED value reaches
// anything the config renders into a log.
//
// AGENTS.md states the no-echo property absolutely. Before this test the
// property had no control at all: a verifier's mutation made a refusal print
// the operator's value verbatim and every lane stayed green. The first version
// of the test then drove 6 of the 17 paths while its comment said "every",
// which is the same defect one level up — a sentence stronger than its test.
// Markers are assembled at run time so they cannot collide with a word a
// message legitimately prints, and so they are not key literals in this
// repository's sources.
func TestNoRefusalEchoesTheSuppliedValue(t *testing.T) {
	marker := func() string {
		return "zz" + strconv.FormatInt(time.Now().UnixNano(), 36) + "mk"
	}

	for _, site := range refusalSites() {
		t.Run(site.rendered, func(t *testing.T) {
			for i, probe := range site.probes(t, marker) {
				env := envWith(t, probe.env)
				_, err := config.LoadFrom(lookupFrom(env))
				if err == nil {
					t.Fatalf("probe %d did not provoke a refusal at all", i)
				}
				msg := err.Error()
				if !strings.Contains(msg, site.rendered) {
					t.Fatalf("probe %d provoked a different refusal (%q), not %q — the row no longer drives its site",
						i, msg, site.rendered)
				}
				for _, supplied := range probe.supplied {
					if strings.Contains(msg, supplied) {
						t.Fatalf("probe %d: the refusal echoes the supplied value back: %q", i, msg)
					}
				}
			}
		})
	}

	// An IGNORED value must not surface either: nothing reads it, so nothing
	// may render it into a log line.
	t.Run("an ignored value never reaches a log", func(t *testing.T) {
		m := marker()
		cfg, err := config.LoadFrom(lookupFrom(envWith(t, map[string]string{
			config.EnvSearchTopology: m,
		})))
		if err != nil {
			t.Fatalf("an ignored value was refused: %v", err)
		}
		if strings.Contains(cfg.String(), m) {
			t.Fatalf("Config.String() carries the ignored value: %s", cfg.String())
		}
		if strings.Contains(fmt.Sprintf("%v", cfg.LogValue()), m) {
			t.Fatalf("Config.LogValue() carries the ignored value")
		}
	})
}

// TestEveryRefusalSiteInTheLoaderHasANoEchoRow is what makes "every refusal
// path" true rather than asserted. It parses internal/config/config.go, finds
// every `v.addf` call — every way this loader can refuse to boot — and requires
// the table above to account for all of them, by format string and by count.
//
// A refusal added without a row is red. A row whose format string no longer
// exists is red. A row that silently starts covering a second site is red.
func TestEveryRefusalSiteInTheLoaderHasANoEchoRow(t *testing.T) {
	found := addfFormatsIn(t, "config.go")
	if len(found) == 0 {
		t.Fatal("no v.addf calls found in config.go: the guard is not reading the loader")
	}

	total := 0
	for _, n := range found {
		total += n
	}

	matched := map[string]bool{}
	declared := 0
	for _, site := range refusalSites() {
		declared += site.sites
		var hits []string
		for format := range found {
			if strings.Contains(format, site.format) {
				hits = append(hits, format)
			}
		}
		if len(hits) != 1 {
			t.Fatalf("row %q matches %d refusal format strings in config.go, want exactly 1 (found: %v)",
				site.format, len(hits), hits)
		}
		if matched[hits[0]] {
			t.Fatalf("two rows both claim the refusal %q", hits[0])
		}
		matched[hits[0]] = true
		if got := found[hits[0]]; got != site.sites {
			t.Fatalf("row %q declares %d site(s) but config.go emits that message from %d",
				site.format, site.sites, got)
		}
	}

	for format := range found {
		if !matched[format] {
			t.Fatalf("config.go can refuse with %q and no row in refusalSites() drives it; "+
				"add a row (with a probe, or a written reason why its value cannot be a marker) "+
				"so the no-echo property still covers every refusal", format)
		}
	}
	if declared != total {
		t.Fatalf("refusalSites() declares %d refusal sites, config.go has %d", declared, total)
	}
	t.Logf("no-echo coverage: %d refusal sites across %d distinct messages", total, len(found))
}

// addfFormatsIn returns every `v.addf` format string in a source file, mapped to
// the number of call sites that use it. Concatenated literals are folded; a
// non-literal format string is a failure rather than a silent skip, because a
// format the guard cannot read is a refusal it cannot account for.
func addfFormatsIn(t *testing.T, path string) map[string]int {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}

	formats := map[string]int{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "addf" {
			return true
		}
		if len(call.Args) == 0 {
			t.Fatalf("%s: addf call with no format argument", fset.Position(call.Pos()))
		}
		format, ok := constantString(call.Args[0])
		if !ok {
			t.Fatalf("%s: addf called with a format string the guard cannot read; keep refusal "+
				"messages literal so they can be accounted for", fset.Position(call.Pos()))
		}
		formats[format]++
		return true
	})
	return formats
}

// constantString folds a string literal or a concatenation of them.
func constantString(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(e.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		left, ok := constantString(e.X)
		if !ok {
			return "", false
		}
		right, ok := constantString(e.Y)
		if !ok {
			return "", false
		}
		return left + right, true
	case *ast.ParenExpr:
		return constantString(e.X)
	default:
		return "", false
	}
}

func TestValidateCollectsEveryError(t *testing.T) {
	// ADR-002: "validate() collects all errors rather than returning the first."
	_, err := config.LoadFrom(lookupFrom(map[string]string{
		config.EnvMode:           "production",
		config.EnvHMACKey:        config.DevHMACKey,
		config.EnvAddr:           "not-an-address",
		config.EnvMaxBodyBytes:   "-1",
		config.EnvMaxClockSkew:   "banana",
		config.EnvRequestTimeout: "0s",
	}))
	if err == nil {
		t.Fatal("expected errors")
	}
	msg := err.Error()
	for _, want := range []string{
		config.EnvHMACKey,
		config.EnvAddr,
		config.EnvMaxBodyBytes,
		config.EnvMaxClockSkew,
		config.EnvRequestTimeout,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("collected error %q is missing %q", msg, want)
		}
	}
}

func TestCheckEnvValidatesACandidateEnvFileWithTheBootCode(t *testing.T) {
	// The seam ADR-002 requires: setup/doctor/CI validate a candidate env file
	// with the same code that boots the process.
	if err := config.CheckEnv(map[string]string{
		config.EnvMode:    "production",
		config.EnvHMACKey: freshKey(t),
	}); err != nil {
		t.Fatalf("CheckEnv rejected a valid production env: %v", err)
	}
	if err := config.CheckEnv(map[string]string{
		config.EnvMode:    "production",
		config.EnvHMACKey: config.DevHMACKey,
	}); err == nil {
		t.Fatal("CheckEnv accepted a production env carrying the dev key")
	}
}

func TestConfigNeverRendersTheKey(t *testing.T) {
	// ADR-002 § Logging and redaction: no process ever logs credentials.
	env := envWith(t, nil)
	cfg, err := config.LoadFrom(lookupFrom(env))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	for _, rendered := range []string{cfg.String(), cfg.LogValue().String()} {
		if strings.Contains(rendered, env[config.EnvHMACKey]) {
			t.Fatalf("rendered config leaks the HMAC key: %s", rendered)
		}
		if !strings.Contains(rendered, "[redacted]") {
			t.Fatalf("rendered config %q does not mark the key redacted", rendered)
		}
	}
}

func TestErrorsNeverEchoTheKeyValue(t *testing.T) {
	secretish := "dev-" + freshKey(t)
	_, err := config.LoadFrom(lookupFrom(map[string]string{
		config.EnvMode:    "production",
		config.EnvHMACKey: secretish,
	}))
	if err == nil {
		t.Fatal("expected refusal")
	}
	if strings.Contains(err.Error(), secretish) {
		t.Fatalf("config error echoes the rejected key material: %s", err.Error())
	}
}

func TestDurationsAndSizesParse(t *testing.T) {
	cfg, err := config.LoadFrom(lookupFrom(envWith(t, map[string]string{
		config.EnvMaxClockSkew:   "90s",
		config.EnvMaxBodyBytes:   "4096",
		config.EnvRequestTimeout: "2s",
		config.EnvAddr:           "127.0.0.1:9100",
	})))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if cfg.MaxClockSkew != 90*time.Second {
		t.Errorf("MaxClockSkew = %v", cfg.MaxClockSkew)
	}
	if cfg.MaxBodyBytes != 4096 {
		t.Errorf("MaxBodyBytes = %d", cfg.MaxBodyBytes)
	}
	if cfg.RequestTimeout != 2*time.Second {
		t.Errorf("RequestTimeout = %v", cfg.RequestTimeout)
	}
	if cfg.Addr != "127.0.0.1:9100" {
		t.Errorf("Addr = %q", cfg.Addr)
	}
}

// TestDefaultsMatchTheCanonicalContract pins the two numbers the contract owns
// against their LITERAL values, not against the constants themselves. The old
// assertions compared cfg.MaxClockSkew to config.DefaultMaxClockSkew, which is
// a tautology: changing the constant moved the expectation with it, so
// widening the replay window from 5 minutes to 30 days left CI green.
func TestDefaultsMatchTheCanonicalContract(t *testing.T) {
	// Contract: "the skew is then computed on plain int64 seconds against a
	// window of ±300 s" — api/search-internal.openapi.yaml,
	// components.securitySchemes.hmacSignature.
	if config.DefaultMaxClockSkew != 300*time.Second {
		t.Errorf("DefaultMaxClockSkew = %v; the canonical contract fixes the window at 300s", config.DefaultMaxClockSkew)
	}
	// Contract: "A body above MAX_INTERNAL_BODY_BYTES (default 1 MiB)".
	if config.DefaultMaxBodyBytes != 1<<20 {
		t.Errorf("DefaultMaxBodyBytes = %d; the canonical contract fixes the default at 1 MiB (1048576)", config.DefaultMaxBodyBytes)
	}
	// The production ceiling may not be wider than the contract's window.
	if config.MaxProductionClockSkew > 300*time.Second {
		t.Errorf("MaxProductionClockSkew = %v; production must not accept a window wider than the contract's 300s", config.MaxProductionClockSkew)
	}
}

// TestProductionRefusesAnOverwideSkewWindow: with no nonce store at M0 the
// timestamp window IS the replay bound, so an operator must not be able to
// widen it without noticing.
func TestProductionRefusesAnOverwideSkewWindow(t *testing.T) {
	for _, skew := range []string{"301s", "10m", "1h", "8760h"} {
		t.Run(skew, func(t *testing.T) {
			_, err := config.LoadFrom(lookupFrom(envWith(t, map[string]string{
				config.EnvMode:         "production",
				config.EnvMaxClockSkew: skew,
			})))
			if err == nil {
				t.Fatalf("production accepted a %s replay window", skew)
			}
			if !strings.Contains(err.Error(), config.EnvMaxClockSkew) {
				t.Fatalf("the refusal does not name the variable: %s", err.Error())
			}
			if !strings.Contains(err.Error(), "5m0s") {
				t.Fatalf("the refusal does not state the ceiling: %s", err.Error())
			}
		})
	}
}

func TestProductionAcceptsAWindowAtOrBelowTheCeiling(t *testing.T) {
	for _, skew := range []string{"1s", "60s", "299s", "300s", "5m"} {
		if _, err := config.LoadFrom(lookupFrom(envWith(t, map[string]string{
			config.EnvMode:         "production",
			config.EnvMaxClockSkew: skew,
		}))); err != nil {
			t.Errorf("production refused a %s window, which is at or below the ceiling: %v", skew, err)
		}
	}
}

// The body is buffered before the signature can be verified, so the cap is the
// memory bound on an unauthenticated path.
func TestProductionRefusesAnOverlargeBodyCap(t *testing.T) {
	for _, size := range []string{"8388609", "10737418240", "1099511627776"} {
		t.Run(size, func(t *testing.T) {
			_, err := config.LoadFrom(lookupFrom(envWith(t, map[string]string{
				config.EnvMode:         "production",
				config.EnvMaxBodyBytes: size,
			})))
			if err == nil {
				t.Fatalf("production accepted a %s-byte body cap", size)
			}
			if !strings.Contains(err.Error(), config.EnvMaxBodyBytes) {
				t.Fatalf("the refusal does not name the variable: %s", err.Error())
			}
		})
	}
}

func TestProductionAcceptsABodyCapAtOrBelowTheCeiling(t *testing.T) {
	for _, size := range []string{"1024", "1048576", "8388608"} {
		if _, err := config.LoadFrom(lookupFrom(envWith(t, map[string]string{
			config.EnvMode:         "production",
			config.EnvMaxBodyBytes: size,
		}))); err != nil {
			t.Errorf("production refused a %s-byte cap, which is at or below the ceiling: %v", size, err)
		}
	}
}

// Development may exceed both ceilings — and the boot path says so, which
// TestDevelopmentBootWarnsAboutTheRelaxedMode in cmd/ checks end to end.
func TestDevelopmentMayExceedTheProductionCeilings(t *testing.T) {
	cfg, err := config.LoadFrom(lookupFrom(envWith(t, map[string]string{
		config.EnvMode:         "development",
		config.EnvMaxClockSkew: "1h",
		config.EnvMaxBodyBytes: "1073741824",
	})))
	if err != nil {
		t.Fatalf("development refused a widened configuration: %v", err)
	}
	if !cfg.ExceedsProductionCeilings() {
		t.Fatal("ExceedsProductionCeilings() = false for a configuration production would refuse; the boot warning depends on this")
	}
}

func TestAConfigurationInsideTheCeilingsDoesNotClaimToExceedThem(t *testing.T) {
	cfg, err := config.LoadFrom(lookupFrom(envWith(t, nil)))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if cfg.ExceedsProductionCeilings() {
		t.Fatal("ExceedsProductionCeilings() = true for the defaults")
	}
}

// CheckEnv must report the same refusals, so doctor and CI agree with boot.
func TestCheckEnvReportsTheCeilingRefusals(t *testing.T) {
	base := map[string]string{config.EnvMode: "production", config.EnvHMACKey: freshKey(t)}

	if err := config.CheckEnv(base); err != nil {
		t.Fatalf("CheckEnv rejected a valid production env: %v", err)
	}

	wide := map[string]string{}
	for k, v := range base {
		wide[k] = v
	}
	wide[config.EnvMaxClockSkew] = "24h"
	if err := config.CheckEnv(wide); err == nil {
		t.Fatal("CheckEnv accepted a production env with a 24h replay window; doctor would then disagree with boot")
	}

	big := map[string]string{}
	for k, v := range base {
		big[k] = v
	}
	big[config.EnvMaxBodyBytes] = "10737418240"
	if err := config.CheckEnv(big); err == nil {
		t.Fatal("CheckEnv accepted a production env with a 10 GiB body cap")
	}
}

// The ceiling refusal must not turn into a disclosure channel for the rest of
// the configuration.
func TestCeilingRefusalsEchoNoOtherConfiguration(t *testing.T) {
	key := freshKey(t)
	_, err := config.LoadFrom(lookupFrom(map[string]string{
		config.EnvMode:         "production",
		config.EnvHMACKey:      key,
		config.EnvMaxClockSkew: "24h",
		config.EnvAddr:         "10.1.2.3:9999",
	}))
	if err == nil {
		t.Fatal("expected a refusal")
	}
	for _, secret := range []string{key, "10.1.2.3", "9999"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the ceiling refusal echoes %q: %s", secret, err.Error())
		}
	}
}
