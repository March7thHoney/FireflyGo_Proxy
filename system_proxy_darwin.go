//go:build darwin
// +build darwin

package main

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

type darwinProxyEndpoint struct {
	enabled bool
	server  string
	port    string
}

type darwinProxySettings struct {
	web    darwinProxyEndpoint
	secure darwinProxyEndpoint
}

var darwinProxyState = struct {
	sync.Mutex
	captured bool
	previous map[string]darwinProxySettings
}{}

func enabledNetworkServices() ([]string, error) {
	out, err := exec.Command("networksetup", "-listallnetworkservices").CombinedOutput()
	if err != nil {
		return nil, formatCommandError("list network services", err, out)
	}

	var services []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "An asterisk") || strings.HasPrefix(line, "*") {
			continue
		}
		services = append(services, line)
	}

	if len(services) == 0 {
		return nil, fmt.Errorf("no enabled network services found")
	}

	return services, nil
}

func getProxySettings(service string) (darwinProxySettings, error) {
	web, webErr := getProxyEndpoint("-getwebproxy", service)
	secure, secureErr := getProxyEndpoint("-getsecurewebproxy", service)
	return darwinProxySettings{
		web:    web,
		secure: secure,
	}, errors.Join(webErr, secureErr)
}

func getProxyEndpoint(flag string, service string) (darwinProxyEndpoint, error) {
	out, err := exec.Command("networksetup", flag, service).CombinedOutput()
	if err != nil {
		return darwinProxyEndpoint{}, formatCommandError(flag+" "+service, err, out)
	}

	values := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			values[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}

	return darwinProxyEndpoint{
		enabled: values["Enabled"] == "Yes",
		server:  values["Server"],
		port:    values["Port"],
	}, nil
}

func setProxyForServices(services []string, host string, port string) error {
	var errs []error
	for _, service := range services {
		errs = append(errs,
			runNetworkSetup("-setwebproxy", service, host, port),
			runNetworkSetup("-setsecurewebproxy", service, host, port),
			runNetworkSetup("-setwebproxystate", service, "on"),
			runNetworkSetup("-setsecurewebproxystate", service, "on"),
		)
	}

	return errors.Join(errs...)
}

func restoreProxySettings(settings map[string]darwinProxySettings) error {
	var errs []error
	for service, setting := range settings {
		if setting.web.server != "" && setting.web.port != "" {
			errs = append(errs, runNetworkSetup("-setwebproxy", service, setting.web.server, setting.web.port))
		}
		errs = append(errs, runNetworkSetup("-setwebproxystate", service, proxyState(setting.web.enabled)))

		if setting.secure.server != "" && setting.secure.port != "" {
			errs = append(errs, runNetworkSetup("-setsecurewebproxy", service, setting.secure.server, setting.secure.port))
		}
		errs = append(errs, runNetworkSetup("-setsecurewebproxystate", service, proxyState(setting.secure.enabled)))
	}

	return errors.Join(errs...)
}

func disableProxyForServices(services []string) error {
	var errs []error
	for _, service := range services {
		errs = append(errs,
			runNetworkSetup("-setwebproxystate", service, "off"),
			runNetworkSetup("-setsecurewebproxystate", service, "off"),
		)
	}

	return errors.Join(errs...)
}

func proxyState(enabled bool) string {
	if enabled {
		return "on"
	}
	return "off"
}

func runNetworkSetup(args ...string) error {
	out, err := exec.Command("networksetup", args...).CombinedOutput()
	if err != nil {
		return formatCommandError("networksetup "+strings.Join(args, " "), err, out)
	}
	return nil
}

func formatCommandError(action string, err error, out []byte) error {
	msg := strings.TrimSpace(string(out))
	if msg == "" {
		return fmt.Errorf("%s: %w", action, err)
	}
	return fmt.Errorf("%s: %w: %s", action, err, msg)
}

func captureProxySettings(services []string) (map[string]darwinProxySettings, error) {
	settings := make(map[string]darwinProxySettings, len(services))
	var errs []error

	for _, service := range services {
		proxySettings, err := getProxySettings(service)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		settings[service] = proxySettings
	}

	if err := errors.Join(errs...); err != nil {
		return nil, err
	}

	return settings, nil
}

func setProxy(enable bool, host string, port string) error {
	services, err := enabledNetworkServices()
	if err != nil {
		return err
	}

	darwinProxyState.Lock()
	defer darwinProxyState.Unlock()

	if enable {
		if host == "" || port == "" {
			return fmt.Errorf("host and port are required to enable proxy")
		}

		if !darwinProxyState.captured {
			settings, err := captureProxySettings(services)
			if err != nil {
				return err
			}
			darwinProxyState.previous = settings
			darwinProxyState.captured = true
		}

		if err := setProxyForServices(services, host, port); err != nil {
			restoreErr := restoreProxySettings(darwinProxyState.previous)
			darwinProxyState.previous = nil
			darwinProxyState.captured = false
			return errors.Join(err, restoreErr)
		}
		return nil
	}

	if darwinProxyState.captured {
		err := restoreProxySettings(darwinProxyState.previous)
		if err == nil {
			darwinProxyState.previous = nil
			darwinProxyState.captured = false
		}
		return err
	}

	return disableProxyForServices(services)
}
