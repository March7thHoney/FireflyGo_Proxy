//go:build darwin
// +build darwin

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func runWithAdmin(exePath string, env []string) error {
	command := shellQuote(exePath)
	if len(env) > 0 {
		command = strings.Join(shellEnvAssignments(env), " ") + " " + command
	}
	command += " >/dev/null 2>&1 &"

	script := fmt.Sprintf("do shell script %s with administrator privileges", appleScriptString(command))
	cmd := exec.Command("osascript", "-e", script)
	return cmd.Run()
}

func shellEnvAssignments(env []string) []string {
	assignments := make([]string, 0, len(env))
	for _, value := range env {
		key, val, ok := strings.Cut(value, "=")
		if !ok || key == "" {
			continue
		}
		assignments = append(assignments, key+"="+shellQuote(val))
	}
	return assignments
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func appleScriptString(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return `"` + value + `"`
}
