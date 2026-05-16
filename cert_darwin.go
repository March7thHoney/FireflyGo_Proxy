//go:build darwin
// +build darwin

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
)

const darwinSystemKeychain = "/Library/Keychains/System.keychain"

func installCA(absPath string) error {
	cert, err := readCertificate(absPath)
	if err != nil {
		return err
	}

	exists, err := certificateExistsInKeychain(cert, darwinSystemKeychain)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	cmd := exec.Command(
		"security",
		"add-trusted-cert",
		"-d",
		"-r", "trustRoot",
		"-k", darwinSystemKeychain,
		absPath,
	)

	if out, err := cmd.CombinedOutput(); err != nil {
		return formatCommandError("install CA into macOS system keychain", err, out)
	}

	return nil
}

func readCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA certificate: %w", err)
	}

	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}

	cert, err := x509.ParseCertificate(data)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	return cert, nil
}

func certificateExistsInKeychain(cert *x509.Certificate, keychain string) (bool, error) {
	out, err := exec.Command("security", "find-certificate", "-a", "-p", keychain).CombinedOutput()
	if err != nil {
		return false, formatCommandError("read macOS system keychain", err, out)
	}

	remaining := out
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return false, nil
		}
		if block.Type == "CERTIFICATE" && bytes.Equal(block.Bytes, cert.Raw) {
			return true, nil
		}
		remaining = rest
	}
}
