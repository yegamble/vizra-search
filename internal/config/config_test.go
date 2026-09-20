package config_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yegamble/vizra-search/internal/config"
)

// strongKey is a 64-hex-character key: 32 bytes of entropy expressed as hex.
const strongKey = "9f2c1d7a4b3e6f80c5a91d2e3f4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"

func envWith(overrides map[string]string) map[string]string {
	base := map[string]string{
		config.EnvHMACKey: strongKey,
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
	cfg, err := config.LoadFrom(lookupFrom(envWith(nil)))
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
			env := envWith(map[string]string{config.EnvMode: "production"})
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
	cfg, err := config.LoadFrom(lookupFrom(envWith(map[string]string{
		config.EnvMode: "production",
	})))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	if string(cfg.HMACKey) != strongKey {
		t.Fatalf("HMACKey not carried through")
	}
	if !cfg.Mode.IsProduction() {
		t.Fatalf("Mode.IsProduction() = false")
	}
}

func TestDevelopmentModeStillRefusesAnEmptyKey(t *testing.T) {
	env := envWith(map[string]string{config.EnvMode: "development"})
	delete(env, config.EnvHMACKey)
	if _, err := config.LoadFrom(lookupFrom(env)); err == nil {
		t.Fatal("development mode accepted an empty HMAC key; unauthenticated internal endpoints must be impossible")
	}
}

func TestDevelopmentModeAcceptsTheDevKey(t *testing.T) {
	cfg, err := config.LoadFrom(lookupFrom(envWith(map[string]string{
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
	_, err := config.LoadFrom(lookupFrom(envWith(map[string]string{
		config.EnvMode: "staging",
	})))
	if err == nil {
		t.Fatal("an unrecognised mode must fail closed, not fall back to development")
	}
	if !strings.Contains(err.Error(), config.EnvMode) {
		t.Fatalf("error %q does not name the offending variable", err.Error())
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
		config.EnvHMACKey: strongKey,
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
	cfg, err := config.LoadFrom(lookupFrom(envWith(nil)))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	for _, rendered := range []string{cfg.String(), cfg.LogValue().String()} {
		if strings.Contains(rendered, strongKey) {
			t.Fatalf("rendered config leaks the HMAC key: %s", rendered)
		}
		if !strings.Contains(rendered, "[redacted]") {
			t.Fatalf("rendered config %q does not mark the key redacted", rendered)
		}
	}
}

func TestErrorsNeverEchoTheKeyValue(t *testing.T) {
	secretish := "dev-" + strongKey
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
	cfg, err := config.LoadFrom(lookupFrom(envWith(map[string]string{
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
