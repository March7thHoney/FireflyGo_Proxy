package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
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

func main() {
	redirectHost := flag.String("r", "127.0.0.1:21000", "redirect target host")
	blockedStr := flag.String("b", "", "comma separated list of blocked ports")
	proxyPort := flag.Int("p", 0, "proxy listen port (default: auto)")
	exePath := flag.String("e", "", "path to the executable")
	parentPID := flag.Int("parent-pid", 0, "parent process id to watch")
	noSys := flag.Bool("no-sys", false, "skip certificate installation and system proxy setup")
	flag.Parse()

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
	addr := ":" + port
	proxyAddr := "127.0.0.1"
	proxyEndpoint := proxyAddr + ":" + port

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
		if matchDomain(domain, RedirectDomains) {
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
				http.StatusOK,
				"",
			)
		}

		if matchDomain(host, RedirectDomains) {
			if matchURL(path, BlockUrls) {
				full := req.URL.String()
				zlog.Warn().Str("url", full).Msg("Blocked URL")
				return req, goproxy.NewResponse(
					req,
					goproxy.ContentTypeText,
					http.StatusNotFound,
					`{\n"message": "blocked by proxy",\n,"success": false,\n"retcode": -1\n}`,
				)
			}
			full := req.URL.String()
			if containsURL(full, ForceRedirectOnUrlContains) {

				zlog.Info().
					Str("from_url", full).
					Str("raw_query", rawQuery).
					Msg("Force redirect")

				req.URL.Scheme = "http"
				req.URL.Host = *redirectHost
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
			req.URL.Scheme = "http"
			req.URL.Host = *redirectHost
			req.URL.RawQuery = rawQuery
			req.RequestURI = ""
			zlog.Info().Str("to_url", req.URL.String()).Msg("Redirected domain")
			return req, nil
		}

		zlog.Warn().Str("url", req.URL.String()).Msg("PASS URL")
		return req, nil
	})

	srv := &http.Server{
		Addr:              addr,
		Handler:           proxy,
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
