//go:build darwin
// +build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
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

	command := fmt.Sprintf(
		"cd %s && %s > /dev/null 2>&1 &",
		shellQuote(workDir),
		strings.Join(args, " "),
	)
	script := fmt.Sprintf("do shell script %s with administrator privileges", appleScriptString(command))

	if out, err := exec.Command("osascript", "-e", script).CombinedOutput(); err != nil {
		return false, formatCommandError("relaunch proxy as admin", err, out)
	}

	return true, nil
}
