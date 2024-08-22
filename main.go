package main

import (
	"flag"
	"fmt"
	"net/http"
	"sync"
)

func sendRequest(client *http.Client, req *http.Request) (*http.Response, error) {
	return client.Do(req)
}

func newRequest(method, url, host, xHost, xForwardedHost string) (*http.Request, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Host = host
	if xHost != "" {
		req.Header.Set("X-Host", xHost)
	}
	if xForwardedHost != "" {
		req.Header.Set("X-Forwarded-Host", xForwardedHost)
	}
	return req, nil
}

func handleRedirects(client *http.Client, url, initialHost string) {
	attempts := []struct {
		host           string
		xHost          string
		xForwardedHost string
	}{
		{host: initialHost},
		{host: initialHost, xHost: "google.com"},
		{host: initialHost, xHost: "google.com", xForwardedHost: "google.com"},
	}

	var wg sync.WaitGroup
	for i, attempt := range attempts {
		wg.Add(1)
		go func(i int, attempt struct {
			host           string
			xHost          string
			xForwardedHost string
		}) {
			defer wg.Done()
			req, err := newRequest("GET", url, attempt.host, attempt.xHost, attempt.xForwardedHost)
			if err != nil {
				fmt.Printf("Attempt %d: Error creating request: %v\n", i+1, err)
				return
			}
			resp, err := sendRequest(client, req)
			if err != nil {
				fmt.Printf("Attempt %d: Error sending request: %v\n", i+1, err)
				return
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusFound {
				location := resp.Header.Get("Location")
				fmt.Printf("Attempt %d: Redirected to: %s\n", i+1, location)
			} else {
				fmt.Printf("Attempt %d: Status code: %d\n", i+1, resp.StatusCode)
			}
		}(i, attempt)
	}
	wg.Wait()
}

func main() {
	url := flag.String("url", "http://www.vulnerable.com", "URL to test")
	initialHost := flag.String("host", "google.com", "Initial host")
	flag.Parse()

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	handleRedirects(client, *url, *initialHost)
}
