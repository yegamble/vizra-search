package buildinfo_test

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/yegamble/vizra-search/internal/buildinfo"
)

// TestSearchSchemaVersionIsAbsent pins the Q-001 obligation: "it reports no
// search_schema_version until it owns migrations". When vizra-search gains its
// migration directory, this test is replaced in the same PR that adds it — it
// is not a placeholder, it is the assertion that the M0 answer is *absent*
// rather than guessed.
func TestSearchSchemaVersionIsAbsent(t *testing.T) {
	if v := buildinfo.SearchSchemaVersion(); v != nil {
		t.Fatalf("SearchSchemaVersion() = %d; this service owns no migrations, so the honest answer is nil (JSON null)", *v)
	}
}

// TestUnknownBuildTimeIsAValidTimestamp matters because the canonical contract
// declares built_at as an RFC 3339 date-time. An unstamped build must still
// emit something the contract accepts, or `go run` produces a response that
// violates the contract it claims to implement.
func TestUnknownBuildTimeIsAValidTimestamp(t *testing.T) {
	parsed, err := time.Parse(time.RFC3339, buildinfo.UnknownBuildTime)
	if err != nil {
		t.Fatalf("UnknownBuildTime %q is not RFC 3339: %v", buildinfo.UnknownBuildTime, err)
	}
	if parsed.Unix() != 0 {
		t.Errorf("UnknownBuildTime = %v; the epoch is what makes an unstamped build obvious", parsed)
	}
}

func TestDefaultBuildTimeIsTheUnknownPlaceholder(t *testing.T) {
	// A plain `go build` sets no ldflags, so the default must be the valid
	// placeholder rather than the free-form "unknown".
	if _, err := time.Parse(time.RFC3339, buildinfo.BuildTime); err != nil {
		t.Fatalf("BuildTime default %q is not RFC 3339: %v", buildinfo.BuildTime, err)
	}
}

func TestImageDigestIsNilOutsideAnImage(t *testing.T) {
	// The contract declares image_digest as nullable. A binary built outside
	// an image has no digest, and must say so rather than report "unknown".
	if d := buildinfo.ImageDigest(); d != nil {
		t.Fatalf("ImageDigest() = %q for a binary built without -ldflags", *d)
	}
}

func TestGoVersionReportsTheRealToolchain(t *testing.T) {
	if got := buildinfo.GoVersion(); got != runtime.Version() {
		t.Fatalf("GoVersion() = %q, want %q", got, runtime.Version())
	}
	if !strings.HasPrefix(buildinfo.GoVersion(), "go1.") {
		t.Fatalf("GoVersion() = %q", buildinfo.GoVersion())
	}
}

func TestServiceNameIsTheReleaseRecordComponentName(t *testing.T) {
	// ADR-002 § Release and deploy: components.{core,user,search}.
	if buildinfo.Service != "vizra-search" {
		t.Fatalf("Service = %q", buildinfo.Service)
	}
}
