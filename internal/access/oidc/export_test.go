package oidc

import "time"

// SetClock replaces the clock the JWKS refetch limiter reads.
func SetClock(cfg *Config, now func() time.Time) { cfg.now = now }
