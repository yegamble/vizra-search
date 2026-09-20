package config

import "os"

// osLookupEnv is the only place this package touches the process environment.
func osLookupEnv(key string) (string, bool) { return os.LookupEnv(key) }
