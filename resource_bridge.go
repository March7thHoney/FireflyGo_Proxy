package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"errors"
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

var resourceBridgeRetryDelays = []time.Duration{0, 200 * time.Millisecond, 500 * time.Millisecond}

var resourceBridgeClient = &http.Client{
	Transport: resourceBridgeTransport,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("resource bridge redirect limit exceeded")
		}
		if !isAllowedResourceURL(req.URL) {
			return fmt.Errorf("resource bridge rejected redirect to %s", req.URL.Redacted())
		}
		return nil
	},
}

func isAllowedResourceURL(target *url.URL) bool {
	if target == nil || !strings.EqualFold(target.Scheme, "https") {
		return false
	}
	host := strings.ToLower(target.Hostname())
	for _, spec := range resourceBridgeSpecs {
		source, err := url.Parse(spec.sourcePrefix)
		if err == nil && host == strings.ToLower(source.Hostname()) {
			return true
		}
	}
	return false
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

func forceGatewayIdentityEncoding(req *http.Request) {
	if req != nil && req.URL != nil && req.URL.Path == "/query_gateway" {
		req.Header.Set("Accept-Encoding", "identity")
	}
}

func decodeGatewayBody(body []byte, encoding string) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return body, nil
	case "gzip":
		reader, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer reader.Close()
		return io.ReadAll(reader)
	case "deflate":
		reader, err := zlib.NewReader(bytes.NewReader(body))
		if err == nil {
			defer reader.Close()
			return io.ReadAll(reader)
		}
		rawReader := flate.NewReader(bytes.NewReader(body))
		defer rawReader.Close()
		return io.ReadAll(rawReader)
	default:
		return nil, fmt.Errorf("unsupported gateway content encoding %q", encoding)
	}
}

func rewriteGatewayResponse(resp *http.Response, proxyEndpoint string) *http.Response {
	if resp == nil || resp.Request == nil || resp.Request.URL == nil || resp.Request.URL.Path != "/query_gateway" || resp.Body == nil {
		return resp
	}
	encoding := resp.Header.Get("Content-Encoding")
	rawBody, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(rawBody))
		return resp
	}
	body, err := decodeGatewayBody(rawBody, encoding)
	if err != nil {
		resp.Body = io.NopCloser(bytes.NewReader(rawBody))
		zlog.Warn().Str("encoding", encoding).Err(err).Msg("RESOURCE URL REWRITE SKIPPED")
		return resp
	}
	rewritten, changed := rewriteGatewayResourceURLs(body, proxyEndpoint)
	if !changed {
		resp.Body = io.NopCloser(bytes.NewReader(rawBody))
		zlog.Info().Str("encoding", encoding).Bool("changed", false).Msg("RESOURCE URL REWRITE")
		return resp
	}
	resp.Body = io.NopCloser(bytes.NewReader(rewritten))
	resp.ContentLength = int64(len(rewritten))
	resp.Header.Set("Content-Length", fmt.Sprint(len(rewritten)))
	resp.Header.Del("Content-Encoding")
	resp.Header.Del("Transfer-Encoding")
	resp.TransferEncoding = nil
	resp.Uncompressed = false
	zlog.Info().Str("encoding", encoding).Bool("changed", true).Msg("REWRITE RESOURCE URLS")
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
	started := time.Now()
	resp, attempts, err := doResourceBridgeRequest(upReq)
	if err != nil {
		zlog.Error().Err(err).
			Str("host", upstream.Hostname()).
			Str("path", upstream.EscapedPath()).
			Str("method", req.Method).
			Str("range", req.Header.Get("Range")).
			Int("attempts", attempts).
			Dur("elapsed", time.Since(started)).
			Msg("RESOURCE BRIDGE FAILED")
		return goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusBadGateway, "resource bridge failed"), true
	}
	resp.Request = req
	zlog.Info().
		Str("host", upstream.Hostname()).
		Str("path", upstream.EscapedPath()).
		Str("method", req.Method).
		Str("range", req.Header.Get("Range")).
		Int("attempts", attempts).
		Int("status", resp.StatusCode).
		Dur("elapsed", time.Since(started)).
		Msg("RESOURCE BRIDGE")
	return resp, true
}

func doResourceBridgeRequest(req *http.Request) (*http.Response, int, error) {
	var lastErr error
	for attempt, delay := range resourceBridgeRetryDelays {
		if delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-req.Context().Done():
				timer.Stop()
				return nil, attempt, req.Context().Err()
			case <-timer.C:
			}
		}
		attemptReq := req.Clone(req.Context())
		resp, err := resourceBridgeClient.Do(attemptReq)
		if err != nil {
			lastErr = err
			continue
		}
		if (resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusGatewayTimeout) && attempt+1 < len(resourceBridgeRetryDelays) {
			resp.Body.Close()
			lastErr = fmt.Errorf("upstream returned %s", resp.Status)
			continue
		}
		return resp, attempt + 1, nil
	}
	return nil, len(resourceBridgeRetryDelays), lastErr
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
			written, err := io.Copy(w, resp.Body)
			zlog.Info().Int64("bytes", written).Err(err).Msg("RESOURCE BRIDGE BODY")
		}
	})
}
