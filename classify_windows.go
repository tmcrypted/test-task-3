//go:build windows

package portscan

import (
	"errors"
	"syscall"
)

func isRefused(err error) bool {
	// The Windows syscall package's ECONNREFUSED is a Unix-style synthetic
	// errno; Winsock reports WSAECONNREFUSED (10061) instead.
	return errors.Is(err, syscall.Errno(10061))
}

func isUnreachable(err error) bool {
	return errors.Is(err, syscall.Errno(10050)) || // WSAENETDOWN
		errors.Is(err, syscall.Errno(10051)) || // WSAENETUNREACH
		errors.Is(err, syscall.Errno(10065)) // WSAEHOSTUNREACH
}
