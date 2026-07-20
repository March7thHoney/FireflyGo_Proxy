package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/elazarl/goproxy"
	zlog "github.com/rs/zerolog/log"
)

var ENV_CONFIG = make([]string, 0)

func rawQueryFromRequestURI(requestURI string) string {
	queryStart := strings.IndexByte(requestURI, '?')
	if queryStart == -1 {
		return ""
	}

	rawQuery := requestURI[queryStart+1:]
	if fragmentStart := strings.IndexByte(rawQuery, '#'); fragmentStart != -1 {
		rawQuery = rawQuery[:fragmentStart]
	}
	return rawQuery
}

// parseRedirect accepts a bare host:port (defaults to http) or a full URL like https://march7th.hoyotoon.com, returning the scheme and host to forward to.
func parseRedirect(r string) (scheme, host string) {
	if strings.Contains(r, "://") {
		if u, err := url.Parse(r); err == nil && u.Host != "" {
			return u.Scheme, u.Host
		}
	}
	return "http", r
}

func main() {
	redirectHost := flag.String("r", "127.0.0.1:21000", "redirect target (host:port or full URL)")
	blockedStr := flag.String("b", "", "comma separated list of blocked ports")
	proxyPort := flag.Int("p", 0, "proxy listen port (default: auto)")
	exePath := flag.String("e", "", "path to the executable")
	parentPID := flag.Int("parent-pid", 0, "parent process id to watch")
	noSys := flag.Bool("no-sys", false, "skip certificate installation and system proxy setup")
	filterOnly := flag.Bool("filter-only", false, "apply URL filters without redirecting domains")
	flag.Parse()

	redirectScheme, redirectTarget := parseRedirect(*redirectHost)

	if !*noSys {
		relaunched, err := relaunchWithAdminIfNeeded()
		if err != nil {
			zlog.Error().Err(err).Msg("Failed to relaunch with admin privileges")
			return
		}
		if relaunched {
			zlog.Info().Msg("Relaunched with admin privileges")
			return
		}
	}

	blockedPorts := parseBlockedPorts(*blockedStr)
	port := ""
	if *proxyPort != 0 {
		if *proxyPort < 1 || *proxyPort > 65535 {
			zlog.Error().Int("port", *proxyPort).Msg("Invalid proxy port")
			return
		}
		port = fmt.Sprint(*proxyPort)
	} else {
		port = findFreePort(blockedPorts)
	}
	if port == "-1" {
		zlog.Error().Str("port", port).Msg("No free port available")
		return
	}

	cert, err := setupCertificate(!*noSys)
	if err != nil {
		zlog.Error().Err(err).Msg("Failed setup certificate")
		return
	}
	proxyAddr := "127.0.0.1"
	proxyEndpoint := proxyAddr + ":" + port
	addr := proxyEndpoint

	defer func() {
		if r := recover(); r != nil {
			zlog.Error().
				Interface("panic", r).
				Msg("Unexpected panic")
		}
	}()

	if !*noSys {
		if err := setProxy(true, proxyAddr, port); err != nil {
			zlog.Error().Err(err).Msg("Failed to set system proxy")
			return
		}
		stopProxyRefresh := startProxyRefreshLoop(proxyAddr, port)
		defer func() {
			stopProxyRefresh()
			if err := setProxy(false, "", ""); err != nil {
				zlog.Error().Err(err).Msg("Failed to reset system proxy")
			}
		}()
	} else {
		zlog.Info().Msg("System certificate and proxy setup skipped")
	}

	customCaMitm := &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: goproxy.TLSConfigFromCA(cert)}
	var customAlwaysMitm goproxy.FuncHttpsHandler = func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		domain := cleanHost(host)
		if shouldTunnelWithoutMITM(domain) {
			zlog.Info().Str("host", domain).Msg("TUNNEL CONNECT")
			return goproxy.OkConnect, host
		}
		if shouldMitmHost(domain) {
			return customCaMitm, host
		}
		return goproxy.OkConnect, host
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Logger = log.New(io.Discard, "", 0)
	proxy.Tr = &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: 100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		// Forward to https targets (e.g. the online edge) without verifying its cert, to allow self-signed/edge certs.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	proxy.CertStore = NewCertStorage()
	proxy.OnRequest().HandleConnect(customAlwaysMitm)

	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		host := req.URL.Hostname()
		path := req.URL.Path
		rawQuery := req.URL.RawQuery
		if rawQuery == "" {
			rawQuery = rawQueryFromRequestURI(req.RequestURI)
		}
		if resp, ok := serveResourceBridge(req, proxyEndpoint); ok {
			return req, resp
		}

		if matchDomain(host, AlwaysIgnoreDomains) {
			zlog.Warn().Str("url", req.URL.String()).Msg("PASS URL")
			return req, nil
		}

		if matchURL(path, AlwaysIgnoreUrls) {
			zlog.Warn().Str("url", req.URL.String()).Msg("PASS URL")
			return req, nil
		}

		if matchURL(path, EmptyUrls) {
			full := req.URL.String()
			zlog.Warn().Str("url", full).Msg("Empty URL Response")
			return req, goproxy.NewResponse(
				req,
				goproxy.ContentTypeText,
				http.StatusNotFound,
				"",
			)
		}

		if *filterOnly {
			zlog.Warn().Str("url", req.URL.String()).Msg("PASS URL")
			return req, nil
		}

		if matchDomain(host, RedirectDomains) {
			if matchURL(path, BlockUrls) {
				full := req.URL.String()
				zlog.Warn().Str("url", full).Msg("Blocked URL")
				return req, goproxy.NewResponse(
					req,
					goproxy.ContentTypeText,
					http.StatusNotFound,
					`{"message": "blocked by proxy", "success": false, "retcode": -1}`,
				)
			}
			full := req.URL.String()
			if containsURL(full, ForceRedirectOnUrlContains) {

				zlog.Info().
					Str("from_url", full).
					Str("raw_query", rawQuery).
					Msg("Force redirect")

				req.URL.Scheme = redirectScheme
				req.URL.Host = redirectTarget
				req.Host = redirectTarget
				req.URL.RawQuery = rawQuery
				req.RequestURI = ""
				zlog.Info().Str("to_url", req.URL.String()).Msg("Force redirected")
				return req, nil
			}

			zlog.Info().
				Str("host", host).
				Str("from_url", full).
				Str("raw_query", rawQuery).
				Msg("Redirect domain")
			req.URL.Scheme = redirectScheme
			req.URL.Host = redirectTarget
			req.Host = redirectTarget
			req.URL.RawQuery = rawQuery
			req.RequestURI = ""
			zlog.Info().Str("to_url", req.URL.String()).Msg("Redirected domain")
			return req, nil
		}

		zlog.Warn().Str("url", req.URL.String()).Msg("PASS URL")
		return req, nil
	})
	proxy.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		return rewriteGatewayResponse(resp, proxyEndpoint)
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           resourceBridgeHandler(proxy, proxyEndpoint),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	stop := make(chan os.Signal, 1)
	serverErr := make(chan error, 1)
	parentDone := parentProcessDone(*parentPID)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	if *exePath != "" && exists(*exePath) {
		go func() {
			time.Sleep(1 * time.Second)
			err := runWithAdmin(*exePath, ENV_CONFIG)
			if err != nil {
				zlog.Error().Err(err).Msg("Failed to start exe as admin")
			} else {
				zlog.Info().Str("ExePath", *exePath).Msg("Started exe as admin")
			}
		}()
	}
	go func() {
		zlog.Info().
			Str("ProxyAddress", proxyEndpoint).
			Str("RedirectTo", *redirectHost).
			Str("BlockedPorts", strings.Trim(strings.Join(strings.Fields(fmt.Sprint(blockedPorts)), ","), "[]")).
			Str("ExePath", *exePath).
			Bool("FilterOnly", *filterOnly).
			Msg("Proxy started")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()

	select {
	case <-stop:
	case err := <-serverErr:
		zlog.Error().Err(err).Msg("ListenAndServe failed")
	case <-parentDone:
		zlog.Info().Int("ParentPID", *parentPID).Msg("Parent process exited")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		zlog.Error().Err(err).Msg("Server shutdown error")
	}
}
