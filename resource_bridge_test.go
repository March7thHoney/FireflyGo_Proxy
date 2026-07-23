package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func gatewayBody() []byte {
	payload := strings.Join([]string{
		resourceBridgeSpecs[0].sourcePrefix + "/lua/M_LuaV.bytes",
		resourceBridgeSpecs[1].sourcePrefix + "/asb/M_ArchiveV.bytes",
	}, "\n")
	return []byte(base64.StdEncoding.EncodeToString([]byte(payload)))
}

func compressGatewayBody(t *testing.T, encoding string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	var writer io.WriteCloser
	var err error
	switch encoding {
	case "gzip":
		writer = gzip.NewWriter(&buf)
	case "deflate":
		writer = zlib.NewWriter(&buf)
	case "raw-deflate":
		writer, err = flate.NewWriter(&buf, flate.DefaultCompression)
	default:
		return body
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestRewriteGatewayResourceURLs(t *testing.T) {
	body := gatewayBody()
	rewritten, changed := rewriteGatewayResourceURLs(body, "127.0.0.1:18080")
	if !changed || len(rewritten) != len(body) {
		t.Fatalf("changed=%v len=%d want=%d", changed, len(rewritten), len(body))
	}
	decoded, err := base64.StdEncoding.DecodeString(string(rewritten))
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range resourceBridgeSpecs {
		if bytes.Contains(decoded, []byte(spec.sourcePrefix)) {
			t.Fatalf("source prefix was not rewritten: %s", spec.sourcePrefix)
		}
		prefix, ok := resourceBridgePrefix(spec, "127.0.0.1:18080")
		if !ok || !bytes.Contains(decoded, []byte(prefix)) {
			t.Fatalf("bridge prefix missing: %s", prefix)
		}
	}
}

func TestRewriteGatewayResponseEncodings(t *testing.T) {
	for _, test := range []struct {
		name     string
		encoding string
		wire     string
	}{
		{name: "identity"},
		{name: "gzip", encoding: "gzip", wire: "gzip"},
		{name: "deflate", encoding: "deflate", wire: "deflate"},
		{name: "raw deflate", encoding: "deflate", wire: "raw-deflate"},
		{name: "chunked", wire: "chunked"},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := gatewayBody()
			wireBody := compressGatewayBody(t, test.wire, original)
			reqURL, _ := url.Parse("https://dispatch.example/query_gateway?uid=hidden")
			resp := &http.Response{
				StatusCode:    http.StatusOK,
				Header:        make(http.Header),
				Body:          io.NopCloser(bytes.NewReader(wireBody)),
				ContentLength: int64(len(wireBody)),
				Request:       &http.Request{URL: reqURL},
			}
			if test.encoding != "" {
				resp.Header.Set("Content-Encoding", test.encoding)
			}
			if test.wire == "chunked" {
				resp.ContentLength = -1
				resp.TransferEncoding = []string{"chunked"}
			}
			got := rewriteGatewayResponse(resp, "127.0.0.1:18080")
			body, err := io.ReadAll(got.Body)
			if err != nil {
				t.Fatal(err)
			}
			if len(body) != len(original) || bytes.Equal(body, original) {
				t.Fatalf("gateway body was not rewritten")
			}
			if got.Header.Get("Content-Encoding") != "" || len(got.TransferEncoding) != 0 {
				t.Fatalf("rewritten response retained transfer encoding")
			}
			if got.ContentLength != int64(len(body)) {
				t.Fatalf("content length=%d want=%d", got.ContentLength, len(body))
			}
		})
	}
}

func TestForceGatewayIdentityEncoding(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://dispatch.example/query_gateway", nil)
	req.Header.Set("Accept-Encoding", "gzip, br")
	forceGatewayIdentityEncoding(req)
	if got := req.Header.Get("Accept-Encoding"); got != "identity" {
		t.Fatalf("Accept-Encoding=%q", got)
	}
}

func TestResourceBridgeRedirectPolicy(t *testing.T) {
	allowed, _ := http.NewRequest(http.MethodGet, "https://autopatchos.starrails.com/file", nil)
	if err := resourceBridgeClient.CheckRedirect(allowed, nil); err != nil {
		t.Fatalf("allowed redirect rejected: %v", err)
	}
	for _, target := range []string{
		"http://autopatchos.starrails.com/file",
		"https://example.com/file",
	} {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		if err := resourceBridgeClient.CheckRedirect(req, nil); err == nil {
			t.Fatalf("redirect unexpectedly allowed: %s", target)
		}
	}
	via := make([]*http.Request, 5)
	if err := resourceBridgeClient.CheckRedirect(allowed, via); err == nil {
		t.Fatal("redirect limit was not enforced")
	}
}

func TestResourceBridgeRetries(t *testing.T) {
	oldClient := resourceBridgeClient
	oldDelays := resourceBridgeRetryDelays
	defer func() {
		resourceBridgeClient = oldClient
		resourceBridgeRetryDelays = oldDelays
	}()
	resourceBridgeRetryDelays = []time.Duration{0, 0, 0}

	for _, test := range []struct {
		name       string
		firstError bool
	}{
		{name: "transport error", firstError: true},
		{name: "transient status"},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			resourceBridgeClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				if calls < 3 {
					if test.firstError {
						return nil, errors.New("temporary TLS failure")
					}
					return &http.Response{StatusCode: http.StatusServiceUnavailable, Status: "503 Service Unavailable", Header: make(http.Header), Body: io.NopCloser(strings.NewReader("retry")), Request: req}, nil
				}
				return &http.Response{StatusCode: http.StatusPartialContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: req}, nil
			})}
			req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "https://autopatchcn.bhsr.com/file", nil)
			resp, attempts, err := doResourceBridgeRequest(req)
			if err != nil || resp.StatusCode != http.StatusPartialContent || attempts != 3 || calls != 3 {
				t.Fatalf("status=%v attempts=%d calls=%d err=%v", resp.StatusCode, attempts, calls, err)
			}
			resp.Body.Close()
		})
	}
}

func TestServeResourceBridgeForwardsMethodsAndHeaders(t *testing.T) {
	oldClient := resourceBridgeClient
	oldDelays := resourceBridgeRetryDelays
	defer func() {
		resourceBridgeClient = oldClient
		resourceBridgeRetryDelays = oldDelays
	}()
	resourceBridgeRetryDelays = []time.Duration{0}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		t.Run(method, func(t *testing.T) {
			var upstream *http.Request
			resourceBridgeClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				upstream = req
				return &http.Response{StatusCode: http.StatusPartialContent, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("ok")), Request: req}, nil
			})}
			prefix, ok := resourceBridgePrefix(resourceBridgeSpecs[0], "127.0.0.1:18080")
			if !ok {
				t.Fatal("bridge prefix unavailable")
			}
			req, _ := http.NewRequest(method, prefix+"/lua/M_LuaV.bytes?token=1", nil)
			req.Header.Set("Range", "bytes=0-31")
			req.Header.Set("If-None-Match", "etag")
			resp, handled := serveResourceBridge(req, "127.0.0.1:18080")
			if !handled || resp.StatusCode != http.StatusPartialContent {
				t.Fatalf("handled=%v status=%d", handled, resp.StatusCode)
			}
			resp.Body.Close()
			if upstream.Method != method || upstream.Header.Get("Range") != "bytes=0-31" || upstream.Header.Get("If-None-Match") != "etag" {
				t.Fatalf("upstream request was not preserved")
			}
			if upstream.URL.Scheme != "https" || upstream.URL.Host != "autopatchcn.bhsr.com" || upstream.URL.RawQuery != "token=1" {
				t.Fatalf("unexpected upstream URL: %s", upstream.URL.Redacted())
			}
		})
	}
}
