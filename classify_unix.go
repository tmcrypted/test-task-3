//go:build !windows

package portscan

import (
	"errors"
	"syscall"
)

func isRefused(err error) bool { return errors.Is(err, syscall.ECONNREFUSED) }

func isUnreachable(err error) bool {
	return errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.ENETDOWN)
}
