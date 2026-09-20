// Package buildinfo carries the identity this service reports on /version.
//
// Version, Commit and BuildTime are set at link time with -ldflags -X; the
// Makefile and the Dockerfile both set them. They keep placeholder values in a
// plain `go build` so that an unstamped binary is obvious rather than dishonest.
package buildinfo

import "runtime"

const (
	// Service is the component name in the release record (ADR-002).
	Service = "vizra-search"

	// UnknownValue is what an unstamped build reports for a free-form field.
	UnknownValue = "unknown"

	// UnknownBuildTime is what an unstamped build reports for built_at. The
	// canonical contract declares built_at as an RFC 3339 date-time, so an
	// unstamped build must still emit a valid timestamp; the Unix epoch is
	// obviously not a real build time.
	UnknownBuildTime = "1970-01-01T00:00:00Z"
)

var (
	// Version is the release tag, set with -ldflags.
	Version = UnknownValue
	// Commit is the source commit, set with -ldflags.
	Commit = UnknownValue
	// BuildTime is an RFC 3339 timestamp, set with -ldflags.
	BuildTime = UnknownBuildTime
	// Digest is the image digest, set with -ldflags in an image build and
	// empty for a plain binary.
	Digest = ""
)

// ImageDigest returns the image digest, or nil when the binary was not built
// into an image. The contract declares image_digest as nullable.
func ImageDigest() *string {
	if Digest == "" {
		return nil
	}
	d := Digest
	return &d
}

// GoVersion is the toolchain that built this binary.
func GoVersion() string { return runtime.Version() }

// SearchSchemaVersion is the version of the `search` PostgreSQL schema this
// service owns.
//
// Q-001: "it reports no search_schema_version until it owns migrations". This
// slice ships no migrations, so the answer is deliberately absent — nil, which
// serializes as JSON null — and never a zero or a guess. When vizra-search
// gains its migration directory, this returns the applied version and the test
// that pins it to nil is replaced in the same PR.
func SearchSchemaVersion() *int64 { return nil }
