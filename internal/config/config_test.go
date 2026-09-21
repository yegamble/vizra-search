package config_test

import (
	"errors"
	"fmt"
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
// for the same concept. VIZRA_SEARCH_MODE is core's search TOPOLOGY variable
// (off | managed | external) and means that, and only that, product-wide.

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

// TestNoRefusalEchoesTheSuppliedValue drives EVERY refusal path in the loader
// that names a variable, with a marker assembled at run time as that variable's
// value, and fails if the marker comes back in the error or in anything the
// config renders into a log.
//
// AGENTS.md states the no-echo property absolutely. Until this test existed the
// property had no control at all: a verifier's mutation made a refusal print
// the operator's value verbatim and every lane stayed green. The marker is
// assembled rather than written as a literal so it cannot collide with a
// vocabulary word a message legitimately prints, and so it cannot be mistaken
// for a key literal by TestEveryKeyLiteralInThisRepositoryIsRefused.
func TestNoRefusalEchoesTheSuppliedValue(t *testing.T) {
	marker := func() string {
		return "zz" + strconv.FormatInt(time.Now().UnixNano(), 36) + "marker"
	}

	// Each case supplies the marker as one variable's value and must produce a
	// refusal that names the variable and not the value.
	for _, tc := range []struct {
		name string
		key  string
		// value wraps the marker when the refusal only fires for a particular
		// shape of value.
		value func(marker string) string
	}{
		{"unknown runtime mode", config.EnvMode, func(m string) string { return m }},
		{"listen address", config.EnvAddr, func(m string) string { return m }},
		{"clock skew", config.EnvMaxClockSkew, func(m string) string { return m }},
		{"request timeout", config.EnvRequestTimeout, func(m string) string { return m }},
		{"shutdown grace", config.EnvShutdownGrace, func(m string) string { return m }},
		{"body bytes", config.EnvMaxBodyBytes, func(m string) string { return m }},
		{"the shared secret", config.EnvHMACKey, func(m string) string { return m }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := marker()
			env := envWith(t, map[string]string{tc.key: tc.value(m)})
			_, err := config.LoadFrom(lookupFrom(env))
			if err == nil {
				t.Fatalf("%s=<marker> was accepted; this case must drive a refusal", tc.key)
			}
			if !strings.Contains(err.Error(), tc.key) {
				t.Fatalf("refusal %q does not name %s", err.Error(), tc.key)
			}
			if strings.Contains(err.Error(), m) {
				t.Fatalf("the refusal for %s echoes the supplied value back: %q", tc.key, err.Error())
			}
		})
	}

	// The retired name is refused only for the old vocabulary, so its value
	// cannot be an arbitrary marker. The marker is the SHAPE instead: an
	// oddly-cased, space-padded spelling that the message must not reproduce.
	t.Run("the retired runtime-mode name", func(t *testing.T) {
		raw := "  DeVeLoPmEnT\t"
		_, err := config.LoadFrom(lookupFrom(envWith(t, map[string]string{
			config.EnvSearchTopology: raw,
		})))
		if err == nil {
			t.Fatal("the old vocabulary was accepted")
		}
		if strings.Contains(err.Error(), raw) || strings.Contains(err.Error(), "DeVeLoPmEnT") {
			t.Fatalf("the refusal echoes the value as supplied: %q", err.Error())
		}
	})

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
