package config

import "os"

// osLookupEnv is the only place this module reads the process environment.
// TestNothingOutsideTheSeamReadsTheProcessEnvironment (envseam_test.go) fails
// on any other os.Getenv / os.LookupEnv / os.Environ / os.ExpandEnv /
// syscall.Getenv / syscall.Environ reference in non-test code, anywhere in the
// module, so everything configuration-shaped goes through config.Lookup.
func osLookupEnv(key string) (string, bool) { return os.LookupEnv(key) }
