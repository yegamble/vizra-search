package main_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yegamble/vizra-search/internal/config"
	"github.com/yegamble/vizra-search/internal/hmacauth"
)

const strongKey = "9f2c1d7a4b3e6f80c5a91d2e3f4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b"

var (
	buildOnce sync.Once
	binPath   string
	buildErr  error
)

// binary builds the real command once per test run. These tests exercise the
// shipped entrypoint, not a re-implementation of it.
func binary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "vizra-search-bin")
		if err != nil {
			buildErr = err
			return
		}
		out := filepath.Join(dir, "vizra-search")
		if runtime.GOOS == "windows" {
			out += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", out, ".")
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			buildErr = err
			return
		}
		binPath = out
	})
	if buildErr != nil {
		t.Fatalf("building the command: %v", buildErr)
	}
	return binPath
}

func runWithEnv(t *testing.T, env map[string]string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(binary(t))
	cmd.Env = append(os.Environ(), config.EnvAddr+"=127.0.0.1:0")
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var out, errb syncBuffer
	cmd.Stdout = &out
	cmd.Stderr = &errb

	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("the process did not exit within 10s; it should have refused to boot.\nstdout: %s\nstderr: %s", out.String(), errb.String())
	}
	return out.String(), errb.String(), exitCode
}

// TestProductionBootRefusesTheDevHMACKey is demonstration D3 of the slice, run
// against the real binary rather than against the config package.
func TestProductionBootRefusesTheDevHMACKey(t *testing.T) {
	stdout, stderr, code := runWithEnv(t, map[string]string{
		config.EnvMode:    "production",
		config.EnvHMACKey: config.DevHMACKey,
	})
	if code == 0 {
		t.Fatalf("the process booted with the development key in production mode (exit 0)\nstdout: %s", stdout)
	}
	if !strings.Contains(stderr, config.EnvHMACKey) {
		t.Fatalf("stderr does not name the offending variable: %q", stderr)
	}
	if !strings.Contains(stderr, "development placeholder") {
		t.Fatalf("stderr does not explain the refusal: %q", stderr)
	}
	if strings.Contains(stderr, config.DevHMACKey) || strings.Contains(stdout, config.DevHMACKey) {
		t.Fatalf("the refusal echoes the key value back")
	}
	if strings.Contains(stdout, "starting") {
		t.Fatalf("the server started before the configuration was refused")
	}
}

func TestProductionBootRefusesAnEmptyHMACKey(t *testing.T) {
	_, stderr, code := runWithEnv(t, map[string]string{
		config.EnvMode:    "production",
		config.EnvHMACKey: "",
	})
	if code == 0 {
		t.Fatal("the process booted with no HMAC key")
	}
	if !strings.Contains(stderr, "must be set") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestBootRefusesTheDevKeyWhenTheModeIsOmitted(t *testing.T) {
	// The mode defaults to production, so forgetting the mode variable must
	// not silently relax the refusals.
	_, stderr, code := runWithEnv(t, map[string]string{
		config.EnvHMACKey: config.DevHMACKey,
	})
	if code == 0 {
		t.Fatal("omitting the mode allowed the development key to boot")
	}
	if !strings.Contains(stderr, "development placeholder") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestVersionSubcommandReportsIdentity(t *testing.T) {
	cmd := exec.Command(binary(t), "version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version: %v (%s)", err, out)
	}
	if !strings.Contains(string(out), "vizra-search") {
		t.Fatalf("version output = %q", out)
	}
}

// TestTheServiceServesOverRealTCP boots the shipped binary on a real port and
// exercises the boundary end to end: a signed request answers not_indexed, an
// unsigned one is rejected, and SIGTERM drains.
func TestTheServiceServesOverRealTCP(t *testing.T) {
	addr := freeAddr(t)

	cmd := exec.Command(binary(t))
	cmd.Env = append(os.Environ(),
		config.EnvMode+"=production",
		config.EnvHMACKey+"="+strongKey,
		config.EnvAddr+"="+addr,
	)
	var out syncBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})

	base := "http://" + addr
	waitForHealthy(t, base+"/healthz", &out)

	// /readyz is ready, and says the index does not exist.
	ready := getJSON(t, base+"/readyz")
	if ready["status"] != "ok" {
		t.Fatalf("/readyz status = %v, want ok", ready["status"])
	}

	// /version reports a null search_schema_version.
	resp, err := http.Get(base + "/version")
	if err != nil {
		t.Fatalf("GET /version: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("/version is not JSON: %s", raw)
	}
	if string(fields["search_schema_version"]) != "null" {
		t.Fatalf("search_schema_version = %s, want null", fields["search_schema_version"])
	}

	// An unsigned internal call is refused over the wire.
	unsigned, err := http.Post(base+"/internal/v1/search", "application/json",
		strings.NewReader(`{"query":"x","viewer":{"is_anonymous":true,"role":"anonymous"},"site":{"handle":"default"}}`))
	if err != nil {
		t.Fatalf("unsigned POST: %v", err)
	}
	_ = unsigned.Body.Close()
	if unsigned.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned /internal/v1/search = %d, want 401", unsigned.StatusCode)
	}

	// A signed one answers not_indexed.
	body := []byte(`{"query":"sunset","viewer":{"is_anonymous":true,"role":"anonymous"},"site":{"handle":"default"}}`)
	req, _ := http.NewRequest(http.MethodPost, base+"/internal/v1/search", bytes.NewReader(body))
	if err := hmacauth.SignRequest([]byte(strongKey), req, body); err != nil {
		t.Fatalf("SignRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	sig := req.Header.Get(hmacauth.HeaderSignature)
	signed, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("signed POST: %v", err)
	}
	signedBody, _ := io.ReadAll(signed.Body)
	_ = signed.Body.Close()
	if signed.StatusCode != http.StatusOK {
		t.Fatalf("signed /internal/v1/search = %d (%s)", signed.StatusCode, signedBody)
	}
	var answer map[string]any
	if err := json.Unmarshal(signedBody, &answer); err != nil {
		t.Fatalf("not JSON: %s", signedBody)
	}
	if answer["status"] != "not_indexed" {
		t.Fatalf("status = %v, want not_indexed", answer["status"])
	}

	// The process log must not carry the secret or the signature.
	if strings.Contains(out.String(), strongKey) || strings.Contains(out.String(), strings.TrimPrefix(sig, "v1=")) {
		t.Fatalf("the process log leaks signature material:\n%s", out.String())
	}

	// SIGTERM drains and exits.
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatalf("signal: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the process exited with %v:\n%s", err, out.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatalf("the process did not drain within 20s:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "draining") {
		t.Fatalf("no drain was logged:\n%s", out.String())
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

func waitForHealthy(t *testing.T, url string, log *syncBuffer) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s never became healthy:\n%s", url, log.String())
}

func getJSON(t *testing.T, url string) map[string]any {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("GET %s is not JSON: %s", url, raw)
	}
	return out
}

// The Dockerfile's HEALTHCHECK invokes this subcommand, so it must work
// without a shell and must fail when nothing is listening.
func TestHealthcheckSubcommandSucceedsAgainstARunningService(t *testing.T) {
	addr := freeAddr(t)
	cmd := exec.Command(binary(t))
	cmd.Env = append(os.Environ(),
		config.EnvMode+"=production",
		config.EnvHMACKey+"="+strongKey,
		config.EnvAddr+"="+addr,
	)
	var out syncBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	waitForHealthy(t, "http://"+addr+"/healthz", &out)

	probe := exec.Command(binary(t), "healthcheck")
	probe.Env = append(os.Environ(),
		config.EnvMode+"=production",
		config.EnvHMACKey+"="+strongKey,
		config.EnvAddr+"="+addr,
	)
	if probeOut, err := probe.CombinedOutput(); err != nil {
		t.Fatalf("healthcheck failed against a healthy service: %v (%s)", err, probeOut)
	}
}

func TestHealthcheckSubcommandFailsWhenNothingIsListening(t *testing.T) {
	probe := exec.Command(binary(t), "healthcheck")
	probe.Env = append(os.Environ(),
		config.EnvMode+"=production",
		config.EnvHMACKey+"="+strongKey,
		config.EnvAddr+"="+freeAddr(t),
	)
	if out, err := probe.CombinedOutput(); err == nil {
		t.Fatalf("healthcheck succeeded with no service listening (%s)", out)
	}
}

func TestUnknownSubcommandIsRefused(t *testing.T) {
	cmd := exec.Command(binary(t), "serve-everything")
	cmd.Env = append(os.Environ(), config.EnvHMACKey+"="+strongKey)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("an unknown subcommand was accepted (%s)", out)
	}
	if !strings.Contains(string(out), "unknown command") {
		t.Fatalf("output = %q", out)
	}
}
