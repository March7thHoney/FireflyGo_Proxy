package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/elazarl/goproxy"
	zlog "github.com/rs/zerolog/log"
)

type resourceBridgeSpec struct {
	code         string
	sourcePrefix string
}

var resourceBridgeSpecs = []resourceBridgeSpec{
	{code: "cn", sourcePrefix: "https://autopatchcn.bhsr.com"},
	{code: "os", sourcePrefix: "https://autopatchos.starrails.com"},
}

var resourceBridgeTransport = &http.Transport{
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	Proxy:                 nil,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          32,
	MaxIdleConnsPerHost:   16,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   15 * time.Second,
	ResponseHeaderTimeout: 30 * time.Second,
}

func resourceBridgePrefix(spec resourceBridgeSpec, proxyEndpoint string) (string, bool) {
	base := "http://" + proxyEndpoint + "/"
	tokenLength := len(spec.sourcePrefix) - len(base)
	if tokenLength < len(spec.code) {
		return "", false
	}
	return base + spec.code + strings.Repeat("x", tokenLength-len(spec.code)), true
}

func rewriteGatewayResourceURLs(body []byte, proxyEndpoint string) ([]byte, bool) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return body, false
	}
	decoded, err := base64.StdEncoding.DecodeString(string(trimmed))
	if err != nil {
		return body, false
	}
	changed := false
	for _, spec := range resourceBridgeSpecs {
		bridgePrefix, ok := resourceBridgePrefix(spec, proxyEndpoint)
		if !ok || len(bridgePrefix) != len(spec.sourcePrefix) {
			continue
		}
		from := []byte(spec.sourcePrefix)
		if bytes.Contains(decoded, from) {
			decoded = bytes.ReplaceAll(decoded, from, []byte(bridgePrefix))
			changed = true
		}
	}
	if !changed {
		return body, false
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(decoded))
	if len(encoded) != len(trimmed) {
		return body, false
	}
	result := append([]byte(nil), body...)
	start := bytes.Index(body, trimmed)
	copy(result[start:start+len(encoded)], encoded)
	return result, true
}

func rewriteGatewayResponse(resp *http.Response, proxyEndpoint string) *http.Response {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil || resp.Request.URL.Path != "/query_gateway" || resp.Body == nil {
		return resp
	}
	if resp.Header.Get("Content-Encoding") != "" {
		return resp
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(body))
		return resp
	}
	rewritten, changed := rewriteGatewayResourceURLs(body, proxyEndpoint)
	resp.Body = io.NopCloser(bytes.NewReader(rewritten))
	resp.ContentLength = int64(len(rewritten))
	resp.Header.Set("Content-Length", fmt.Sprint(len(rewritten)))
	if changed {
		zlog.Info().Str("url", resp.Request.URL.String()).Msg("REWRITE RESOURCE URLS")
	}
	return resp
}

func resourceBridgeTarget(req *http.Request, proxyEndpoint string) (string, bool) {
	if req == nil || req.URL == nil || (req.Method != http.MethodGet && req.Method != http.MethodHead) {
		return "", false
	}
	host := strings.ToLower(req.URL.Hostname())
	if host == "" {
		host = strings.ToLower(cleanHost(req.Host))
	}
	if host != "127.0.0.1" && host != "localhost" {
		return "", false
	}
	for _, spec := range resourceBridgeSpecs {
		bridgePrefix, ok := resourceBridgePrefix(spec, proxyEndpoint)
		if !ok {
			continue
		}
		prefixURL, err := url.Parse(bridgePrefix)
		if err != nil {
			continue
		}
		pathPrefix := prefixURL.Path
		if req.URL.Path != pathPrefix && !strings.HasPrefix(req.URL.Path, pathPrefix+"/") {
			continue
		}
		suffix := strings.TrimPrefix(req.URL.EscapedPath(), pathPrefix)
		target := spec.sourcePrefix + suffix
		if req.URL.RawQuery != "" {
			target += "?" + req.URL.RawQuery
		}
		return target, true
	}
	return "", false
}

func serveResourceBridge(req *http.Request, proxyEndpoint string) (*http.Response, bool) {
	target, ok := resourceBridgeTarget(req, proxyEndpoint)
	if !ok {
		return nil, false
	}
	upstream, err := url.Parse(target)
	if err != nil {
		return goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadGateway, "invalid resource bridge target"), true
	}
	upReq := req.Clone(req.Context())
	upReq.URL = upstream
	upReq.Host = upstream.Host
	upReq.RequestURI = ""
	upReq.Header = req.Header.Clone()
	upReq.Header.Del("Proxy-Connection")
	upReq.Header.Del("Connection")
	resp, err := resourceBridgeTransport.RoundTrip(upReq)
	if err != nil {
		zlog.Error().Err(err).Str("url", target).Msg("RESOURCE BRIDGE FAILED")
		return goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadGateway, "resource bridge failed"), true
	}
	resp.Request = req
	zlog.Info().Str("url", target).Int("status", resp.StatusCode).Msg("RESOURCE BRIDGE")
	return resp, true
}

func resourceBridgeHandler(next http.Handler, proxyEndpoint string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		resp, ok := serveResourceBridge(req, proxyEndpoint)
		if !ok {
			next.ServeHTTP(w, req)
			return
		}
		if resp.Body != nil {
			defer resp.Body.Close()
		}
		_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
		for name, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(resp.StatusCode)
		if req.Method != http.MethodHead && resp.Body != nil {
			_, _ = io.Copy(w, resp.Body)
		}
	})
}
