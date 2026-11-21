package portscan

import (
	"errors"
	"time"
)

const (
	defaultConcurrency    = 100
	defaultConnectTimeout = 500 * time.Millisecond
)

// Option configures a Scanner.
type Option func(*scannerConfig) error

type scannerConfig struct {
	concurrency    int
	connectTimeout time.Duration
}

// WithConcurrency sets the maximum number of concurrent TCP connection attempts.
func WithConcurrency(n int) Option {
	return func(cfg *scannerConfig) error {
		if n < 1 {
			return errors.New("portscan: concurrency must be at least 1")
		}
		cfg.concurrency = n
		return nil
	}
}

// WithConnectTimeout sets the timeout for an individual connection attempt.
func WithConnectTimeout(timeout time.Duration) Option {
	return func(cfg *scannerConfig) error {
		if timeout <= 0 {
			return errors.New("portscan: connect timeout must be positive")
		}
		cfg.connectTimeout = timeout
		return nil
	}
}
