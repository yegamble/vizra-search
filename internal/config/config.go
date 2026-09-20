// Package config is the boot truth for vizra-search.
//
// It follows the seam ADR-002 fixes for the platform: Load reads the process
// environment, LoadFrom reads any lookup function, and CheckEnv validates a
// candidate env file with the same code that boots the process — so setup,
// doctor and CI can never disagree with boot. validate collects every error
// instead of returning the first, and production mode is the default, so an env
// file that forgets to declare its mode still gets the production refusals.
package config

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

// DevHMACKey is the one key value shipped in developer documentation and
// compose overrides. A production process must refuse it. It is a constant so
// that the refusal and the documentation can never drift apart.
const DevHMACKey = "dev-insecure-hmac-key-do-not-use-in-production"

// VectorsHMACKey is the shared secret published in the normative conformance
// vectors, api/search-hmac-testvectors.json "key_utf8". It is exactly 32 bytes
// of mixed-case alphanumerics with 32 distinct byte values, so it passes every
// heuristic in this file — and it is the one key whose documentation is a
// committed file an operator will actually read and copy.
//
// It is refused by EXACT VALUE. The heuristics cannot catch it, and must not be
// widened until they could: a rule broad enough to reject this string would
// reject good keys too.
//
// TestTheVectorsPublishedKeyIsStillTheOneWeRefuse reads the value out of the
// vendored file at test time and fails if this constant drifts from it, so
// re-vendoring a changed vectors file cannot silently un-refuse the key.
// vizra-core refuses the same value on its side; a shared secret is only as
// strong as the weaker of the two loaders.
const VectorsHMACKey = "Ar4Lo8Cq2Ei6Uk0Wn3Sv7Yb1Md5Pt9Xz"

// publishedTestKeys are the key literals committed to THIS repository's own
// test sources. They are as public as the dev key, so production refuses them
// too. TestEveryKeyLiteralInThisRepositoryIsRefused parses the test sources and
// fails if a literal appears that is not listed here, so the list cannot rot.
var publishedTestKeys = []string{
	// internal/hmacauth, internal/httpapi, internal/config, cmd/vizra-search
	"9f2c1d7a4b3e6f80c5a91d2e3f4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
	// the deliberately-wrong key used to forge signatures in tests
	"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
}

// IsPublishedKey reports whether a key is one this repository or the shared
// contract publishes. Such a key is refused in production mode by exact value,
// whatever its length or entropy looks like.
func IsPublishedKey(key string) bool {
	if key == DevHMACKey || key == VectorsHMACKey {
		return true
	}
	for _, published := range publishedTestKeys {
		if key == published {
			return true
		}
	}
	return false
}

// PublishedKeys returns every key value production refuses by exact value. It
// exists so the tests can enumerate them without duplicating the literals.
func PublishedKeys() []string {
	out := make([]string, 0, len(publishedTestKeys)+2)
	out = append(out, DevHMACKey, VectorsHMACKey)
	return append(out, publishedTestKeys...)
}

// Defaults. Every one of them is safe to run with; none of them weakens a
// check.
const (
	DefaultAddr = ":8081"
	// DefaultMaxClockSkew and DefaultMaxBodyBytes are both fixed by the
	// canonical contract: "reject a timestamp more than 300 seconds from its
	// own clock in either direction" and "MAX_INTERNAL_BODY_BYTES (default
	// 1 MiB)".
	DefaultMaxClockSkew   = 300 * time.Second
	DefaultMaxBodyBytes   = int64(1 << 20) // 1 MiB
	DefaultRequestTimeout = 5 * time.Second
	DefaultShutdownGrace  = 15 * time.Second

	// MinProductionKeyBytes is the shortest shared secret a production process
	// will accept. 32 bytes is the HMAC-SHA256 block output size.
	MinProductionKeyBytes = 32

	// MaxProductionClockSkew is the widest replay window a production process
	// will accept. It equals the contract's fixed 300 s: with no nonce store at
	// M0 the timestamp window IS the replay bound, so an operator debugging
	// clock drift must not be able to widen it silently. Development may
	// exceed it and says so in the boot log.
	MaxProductionClockSkew = DefaultMaxClockSkew

	// MaxProductionBodyBytes is the largest request body a production process
	// will buffer. The body is read into memory BEFORE the signature can be
	// verified, so this is the memory bound on an unauthenticated code path.
	// 8 MiB is eight times the contract's 1 MiB default, which leaves room for
	// a larger event batch without turning the pre-auth read into a denial of
	// service.
	MaxProductionBodyBytes = int64(8 << 20)
)

// Environment variable names, in one place so the error messages and the
// documentation cannot drift.
const (
	// EnvHMACKey and EnvMaxBodyBytes are named by the canonical contract
	// (api/search-internal.openapi.yaml, securitySchemes.hmacSignature), so
	// core and search read the same operator-facing names. The rest are
	// process-local and carry the service prefix.
	EnvHMACKey      = "SEARCH_HMAC_KEY"
	EnvMaxBodyBytes = "MAX_INTERNAL_BODY_BYTES"

	EnvMode           = "VIZRA_SEARCH_MODE"
	EnvAddr           = "VIZRA_SEARCH_ADDR"
	EnvMaxClockSkew   = "VIZRA_SEARCH_MAX_CLOCK_SKEW"
	EnvRequestTimeout = "VIZRA_SEARCH_REQUEST_TIMEOUT"
	EnvShutdownGrace  = "VIZRA_SEARCH_SHUTDOWN_GRACE"
)

// ErrInvalidConfig wraps every configuration refusal so callers can match on it
// without parsing text.
var ErrInvalidConfig = errors.New("invalid vizra-search configuration")

// Mode is the boot mode. Production is the default and the strict one.
type Mode string

const (
	ModeProduction  Mode = "production"
	ModeDevelopment Mode = "development"
)

// IsProduction reports whether the strict refusals apply.
func (m Mode) IsProduction() bool { return m == ModeProduction }

// Lookup is the environment seam: os.LookupEnv satisfies it, and so does a map
// built from a candidate env file.
type Lookup func(key string) (value string, ok bool)

// Config is the validated boot configuration.
type Config struct {
	Mode           Mode
	Addr           string
	HMACKey        []byte
	MaxClockSkew   time.Duration
	MaxBodyBytes   int64
	RequestTimeout time.Duration
	ShutdownGrace  time.Duration
}

// String renders the configuration with the shared secret redacted. It exists
// so that a careless %v in a log line cannot leak the key (ADR-002 § Logging
// and redaction).
func (c Config) String() string {
	return fmt.Sprintf(
		"config{mode:%s addr:%s hmac_key:[redacted] max_clock_skew:%s max_body_bytes:%d request_timeout:%s shutdown_grace:%s}",
		c.Mode, c.Addr, c.MaxClockSkew, c.MaxBodyBytes, c.RequestTimeout, c.ShutdownGrace,
	)
}

// LogValue implements slog.LogValuer with the same redaction.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("mode", string(c.Mode)),
		slog.String("addr", c.Addr),
		slog.String("hmac_key", "[redacted]"),
		slog.Duration("max_clock_skew", c.MaxClockSkew),
		slog.Int64("max_body_bytes", c.MaxBodyBytes),
		slog.Duration("request_timeout", c.RequestTimeout),
		slog.Duration("shutdown_grace", c.ShutdownGrace),
	)
}

// CheckEnv validates a candidate env file — represented as a map — with the
// boot code itself, and reports every problem it finds.
func CheckEnv(env map[string]string) error {
	_, err := LoadFrom(func(key string) (string, bool) {
		v, ok := env[key]
		return v, ok
	})
	return err
}

// LoadFrom builds and validates a Config from an arbitrary environment lookup.
func LoadFrom(lookup Lookup) (*Config, error) {
	if lookup == nil {
		return nil, fmt.Errorf("%w: nil environment lookup", ErrInvalidConfig)
	}

	v := &validator{lookup: lookup}
	cfg := &Config{
		Mode:           v.mode(),
		Addr:           v.addr(),
		HMACKey:        nil, // set below, after the mode is known
		MaxClockSkew:   v.duration(EnvMaxClockSkew, DefaultMaxClockSkew),
		MaxBodyBytes:   v.bytes(EnvMaxBodyBytes, DefaultMaxBodyBytes),
		RequestTimeout: v.duration(EnvRequestTimeout, DefaultRequestTimeout),
		ShutdownGrace:  v.duration(EnvShutdownGrace, DefaultShutdownGrace),
	}
	cfg.HMACKey = v.hmacKey(cfg.Mode)
	v.ceilings(cfg)

	if err := v.err(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Load reads the process environment.
func Load() (*Config, error) {
	return LoadFrom(osLookupEnv)
}

type validator struct {
	lookup   Lookup
	problems []string
}

func (v *validator) addf(format string, args ...any) {
	v.problems = append(v.problems, fmt.Sprintf(format, args...))
}

// err returns every collected problem as one error, in a stable order.
func (v *validator) err() error {
	if len(v.problems) == 0 {
		return nil
	}
	problems := append([]string(nil), v.problems...)
	sort.Strings(problems)
	return fmt.Errorf("%w:\n  - %s", ErrInvalidConfig, strings.Join(problems, "\n  - "))
}

func (v *validator) raw(key string) (string, bool) {
	s, ok := v.lookup(key)
	if !ok {
		return "", false
	}
	return s, true
}

// mode defaults to production. An unrecognised value fails closed rather than
// degrading to development.
func (v *validator) mode() Mode {
	raw, ok := v.raw(EnvMode)
	if !ok || strings.TrimSpace(raw) == "" {
		return ModeProduction
	}
	switch Mode(strings.ToLower(strings.TrimSpace(raw))) {
	case ModeProduction:
		return ModeProduction
	case ModeDevelopment:
		return ModeDevelopment
	default:
		v.addf("%s must be %q or %q", EnvMode, ModeProduction, ModeDevelopment)
		// Keep the strict mode so the remaining checks stay strict too.
		return ModeProduction
	}
}

func (v *validator) addr() string {
	raw, ok := v.raw(EnvAddr)
	if !ok || strings.TrimSpace(raw) == "" {
		return DefaultAddr
	}
	raw = strings.TrimSpace(raw)
	if _, _, err := net.SplitHostPort(raw); err != nil {
		v.addf("%s is not a host:port listen address", EnvAddr)
		return DefaultAddr
	}
	return raw
}

func (v *validator) duration(key string, def time.Duration) time.Duration {
	raw, ok := v.raw(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return def
	}
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		v.addf("%s is not a duration (for example 30s, 5m)", key)
		return def
	}
	if d <= 0 {
		v.addf("%s must be greater than zero", key)
		return def
	}
	return d
}

func (v *validator) bytes(key string, def int64) int64 {
	raw, ok := v.raw(key)
	if !ok || strings.TrimSpace(raw) == "" {
		return def
	}
	n, err := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if err != nil {
		v.addf("%s is not an integer number of bytes", key)
		return def
	}
	if n <= 0 {
		v.addf("%s must be greater than zero", key)
		return def
	}
	return n
}

// ceilings refuses a production process that widens either of the two limits
// the contract fixes. Development may exceed them — the boot log says so — but
// production may not, because both sit on the unauthenticated path.
//
// The messages name the offending variable and the ceiling, and nothing else:
// no other configuration value is echoed.
func (v *validator) ceilings(cfg *Config) {
	if !cfg.Mode.IsProduction() {
		return
	}
	if cfg.MaxClockSkew > MaxProductionClockSkew {
		v.addf("%s must not exceed %s in %s mode; the canonical contract fixes the replay window at %s and there is no nonce store to bound it otherwise",
			EnvMaxClockSkew, MaxProductionClockSkew, ModeProduction, MaxProductionClockSkew)
	}
	if cfg.MaxBodyBytes > MaxProductionBodyBytes {
		v.addf("%s must not exceed %d bytes in %s mode; the body is buffered before the signature can be verified, so this is the memory bound on an unauthenticated path",
			EnvMaxBodyBytes, MaxProductionBodyBytes, ModeProduction)
	}
}

// ExceedsProductionCeilings reports whether this configuration relies on limits
// a production process would refuse. It is how the boot path knows to warn in
// development mode.
func (c Config) ExceedsProductionCeilings() bool {
	return c.MaxClockSkew > MaxProductionClockSkew || c.MaxBodyBytes > MaxProductionBodyBytes
}

// placeholderMarkers are substrings that mark a key as a documentation or
// development placeholder. The check is case-insensitive and never echoes the
// rejected value.
var placeholderMarkers = []string{
	"changeme",
	"change-me",
	"do-not-use",
	"donotuse",
	"insecure",
	"placeholder",
	"example",
	"password",
	"secret",
	"sample",
	"dummy",
	"xxxx",
}

var placeholderPrefixes = []string{"dev-", "dev_", "test-", "test_", "local-", "demo-"}

var placeholderExact = []string{"dev", "devkey", "test", "testkey", "local", "demo", "vizra", "vizra-search"}

// hmacKey reads and validates the shared secret. It is never echoed into an
// error message.
func (v *validator) hmacKey(mode Mode) []byte {
	raw, _ := v.raw(EnvHMACKey)
	key := strings.TrimSpace(raw)

	if key == "" {
		// Refused in every mode: an internal endpoint that cannot verify a
		// signature must not exist.
		v.addf("%s must be set", EnvHMACKey)
		return nil
	}

	if !mode.IsProduction() {
		return []byte(key)
	}

	lower := strings.ToLower(key)

	// Exact-value refusals come first: these keys are published — in this
	// repository's own sources, or in the conformance vectors an operator is
	// invited to read — and no heuristic would catch them. No message below
	// ever echoes the value.
	if key == DevHMACKey {
		v.addf("%s is the documented development placeholder and is refused in %s mode", EnvHMACKey, ModeProduction)
		return []byte(key)
	}
	if IsPublishedKey(key) {
		v.addf("%s is a key published in this repository or in the shared conformance vectors and is refused in %s mode; generate a fresh secret (for example `openssl rand -hex 32`)",
			EnvHMACKey, ModeProduction)
		return []byte(key)
	}
	for _, exact := range placeholderExact {
		if lower == exact {
			v.addf("%s looks like a development placeholder and is refused in %s mode", EnvHMACKey, ModeProduction)
			return []byte(key)
		}
	}
	for _, prefix := range placeholderPrefixes {
		if strings.HasPrefix(lower, prefix) {
			v.addf("%s looks like a development placeholder and is refused in %s mode", EnvHMACKey, ModeProduction)
			return []byte(key)
		}
	}
	for _, marker := range placeholderMarkers {
		if strings.Contains(lower, marker) {
			v.addf("%s looks like a development placeholder and is refused in %s mode", EnvHMACKey, ModeProduction)
			return []byte(key)
		}
	}
	if len(key) < MinProductionKeyBytes {
		v.addf("%s must be at least %d bytes in %s mode", EnvHMACKey, MinProductionKeyBytes, ModeProduction)
		return []byte(key)
	}
	if distinctBytes(key) < 8 {
		v.addf("%s must contain at least 8 distinct byte values; a repeated character is not a secret", EnvHMACKey)
		return []byte(key)
	}

	return []byte(key)
}

func distinctBytes(s string) int {
	var seen [256]bool
	n := 0
	for i := 0; i < len(s); i++ {
		if !seen[s[i]] {
			seen[s[i]] = true
			n++
		}
	}
	return n
}
