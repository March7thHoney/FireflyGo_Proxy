//go:build linux
// +build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func relaunchWithAdminIfNeeded() (bool, error) {
	if os.Geteuid() == 0 {
		return false, nil
	}

	exePath, err := os.Executable()
	if err != nil {
		return false, fmt.Errorf("get executable path: %w", err)
	}

	workDir, err := os.Getwd()
	if err != nil {
		return false, fmt.Errorf("get working directory: %w", err)
	}

	args := make([]string, 0, len(os.Args))
	args = append(args, shellQuote(exePath))
	for _, arg := range os.Args[1:] {
		args = append(args, shellQuote(arg))
	}

	logPath := filepath.Join(os.TempDir(), "firefly-go-proxy.log")
	command := fmt.Sprintf(
		"cd %s && nohup %s >> %s 2>&1 &",
		shellQuote(workDir),
		strings.Join(args, " "),
		shellQuote(logPath),
	)

	if pkexecPath, err := exec.LookPath("pkexec"); err == nil {
		if out, err := exec.Command(pkexecPath, "sh", "-c", command).CombinedOutput(); err == nil {
			return true, nil
		} else if _, sudoErr := exec.LookPath("sudo"); sudoErr != nil {
			return false, formatCommandError("relaunch proxy as admin with pkexec", err, out)
		}
	}

	sudoPath, err := exec.LookPath("sudo")
	if err != nil {
		return false, errors.New("pkexec or sudo is required to relaunch with admin privileges")
	}
	if out, err := exec.Command(sudoPath, "sh", "-c", command).CombinedOutput(); err != nil {
		return false, formatCommandError("relaunch proxy as admin with sudo", err, out)
	}

	return true, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func formatCommandError(action string, err error, out []byte) error {
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		return fmt.Errorf("%s: %w", action, err)
	}
	return fmt.Errorf("%s: %w: %s", action, err, msg)
}
