package modules

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"time"

	"github.com/MakFly/vx/pkg/engine"
)

// ProbeResult holds the result of an HTTP probe with metadata
type ProbeResult struct {
	Code        int
	Body        string
	ContentType string
}

func newHTTPClient(cfg *engine.Config) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Timeout: cfg.Timeout,
		Jar:     jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: false,
			},
			DialContext: (&net.Dialer{
				Timeout: 10 * time.Second,
			}).DialContext,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func newNoRedirectClient(cfg *engine.Config) *http.Client {
	c := newHTTPClient(cfg)
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c
}

func doGet(client *http.Client, url string, ua string) (*http.Response, []byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "fr-FR,fr;q=0.9,en;q=0.5")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return resp, nil, err
	}

	return resp, body, nil
}

// DoRequest performs an HTTP request with any method and returns a ProbeResult
func DoRequest(client *http.Client, method, url, ua string) ProbeResult {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return ProbeResult{}
	}
	req.Header.Set("User-Agent", ua)

	resp, err := client.Do(req)
	if err != nil {
		return ProbeResult{}
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return ProbeResult{
		Code:        resp.StatusCode,
		Body:        string(body),
		ContentType: resp.Header.Get("Content-Type"),
	}
}

// IsSPACatchAll detects if an HTTP response body is a SPA framework catch-all page
// (Next.js, React, Vue, Angular, Nuxt) rather than a real response to the request.
func IsSPACatchAll(body string) bool {
	// Next.js signatures
	if strings.Contains(body, "_next/static") || strings.Contains(body, "__NEXT_DATA__") {
		return true
	}
	// Nuxt.js signatures
	if strings.Contains(body, "_nuxt/") || strings.Contains(body, "__NUXT__") {
		return true
	}
	// Generic SPA: full HTML page with framework markers
	if strings.Contains(body, "<!DOCTYPE html>") || strings.Contains(body, "<!doctype html>") {
		bodyLower := strings.ToLower(body)
		// React root div
		if strings.Contains(bodyLower, `id="__next"`) || strings.Contains(bodyLower, `id="root"`) || strings.Contains(bodyLower, `id="app"`) {
			// Must also have stylesheet links (real HTML page, not a simple error)
			if strings.Contains(body, "<link rel=\"stylesheet\"") || strings.Contains(body, "<link rel='stylesheet'") || strings.Contains(body, ".css") {
				return true
			}
		}
		// Vue/Angular markers
		if strings.Contains(bodyLower, "ng-version") || strings.Contains(bodyLower, "v-cloak") || strings.Contains(bodyLower, "data-v-") {
			return true
		}
	}
	return false
}

// IsRealAPIResponse checks if a 200 response is actually an API response
// and not a framework catch-all
func IsRealAPIResponse(r ProbeResult) bool {
	if r.Code != 200 {
		return false
	}
	ct := strings.ToLower(r.ContentType)
	if strings.Contains(ct, "text/html") {
		return !IsSPACatchAll(r.Body)
	}
	return true
}
