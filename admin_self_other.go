//go:build !darwin && !linux
// +build !darwin,!linux

package main

func relaunchWithAdminIfNeeded() (bool, error) {
	return false, nil
}
