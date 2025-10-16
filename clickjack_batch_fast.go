package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type VulnResult struct {
	URL                 string `json:"url"`
	Method              string `json:"method"`
	XFrameOptions       string `json:"x_frame_options"`
	ContentSecurityPolicy string `json:"content_security_policy"`
	PocHTML            string `json:"poc_html"`
}

var (
	headers = map[string]string{
		"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
	}
	vulnResults []VulnResult
)

func timestamp() string {
	return time.Now().Format("20060102_150405")
}

func autoDetectMethod(targetURL string) string {
	client := &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	// Try GET first
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return ""
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err == nil && resp.StatusCode < 500 {
		resp.Body.Close()
		return "GET"
	}
	if resp != nil {
		resp.Body.Close()
	}

	// Try POST if GET failed
	req, err = http.NewRequest("POST", targetURL, nil)
	if err != nil {
		return ""
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err = client.Do(req)
	if err == nil && resp.StatusCode < 500 {
		resp.Body.Close()
		return "POST"
	}
	if resp != nil {
		resp.Body.Close()
	}

	return ""
}

func checkHeaders(targetURL, method string) (string, string) {
	client := &http.Client{
		Timeout: 6 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest(method, targetURL, nil)
	if err != nil {
		fmt.Printf("[!] Error creating request for %s: %v\n", targetURL, err)
		return "", ""
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("[!] Error on %s: %v\n", targetURL, err)
		return "", ""
	}
	defer resp.Body.Close()

	xfo := resp.Header.Get("X-Frame-Options")
	csp := resp.Header.Get("Content-Security-Policy")

	return xfo, csp
}

func generatePocHTML(targetURL, filename string) {
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head><title>Clickjacking PoC</title></head>
<body>
<h2>Clickjacking PoC for %s</h2>
<iframe src="%s" width="800" height="600" style="opacity:0.9;"></iframe>
</body>
</html>`, targetURL, targetURL)

	err := os.WriteFile(filename, []byte(html), 0644)
	if err != nil {
		fmt.Printf("[!] Error writing PoC file: %v\n", err)
	}
}

func analyze(targetURL string) {
	if !strings.HasPrefix(targetURL, "http") {
		targetURL = "http://" + targetURL
	}
	fmt.Printf("\n[+] Scanning: %s\n", targetURL)

	method := autoDetectMethod(targetURL)
	if method == "" {
		fmt.Println("[-] Skipping (method detection failed)")
		return
	}

	fmt.Printf("[+] Method: %s\n", method)
	xfo, csp := checkHeaders(targetURL, method)

	fmt.Printf("    XFO: %s\n", xfo)
	fmt.Printf("    CSP: %s\n", csp)

	if xfo == "" && !strings.Contains(csp, "frame-ancestors") {
		fmt.Println("[!] VULNERABLE! Generating PoC...")
		parsedURL, err := url.Parse(targetURL)
		if err != nil {
			fmt.Printf("[!] Error parsing URL: %v\n", err)
			return
		}
		hostname := strings.Replace(parsedURL.Host, ":", "_", -1)
		htmlFile := fmt.Sprintf("PoC_%s.html", hostname)
		generatePocHTML(targetURL, htmlFile)

		vulnResults = append(vulnResults, VulnResult{
			URL:                 targetURL,
			Method:              method,
			XFrameOptions:       xfo,
			ContentSecurityPolicy: csp,
			PocHTML:            htmlFile,
		})
	} else {
		fmt.Println("[+] Not vulnerable.")
	}
}

func writeOutputs() {
	if len(vulnResults) == 0 {
		fmt.Println("\n[+] No vulnerable sites found.")
		return
	}

	fname := fmt.Sprintf("vulnerable_%s", timestamp())
	txtFile := fname + ".txt"
	jsonFile := fname + ".json"

	// Write TXT file
	txtContent, err := os.Create(txtFile)
	if err != nil {
		fmt.Printf("[!] Error creating TXT file: %v\n", err)
		return
	}
	defer txtContent.Close()

	for _, entry := range vulnResults {
		txtContent.WriteString(entry.URL + "\n")
	}

	// Write JSON file
	jsonContent, err := os.Create(jsonFile)
	if err != nil {
		fmt.Printf("[!] Error creating JSON file: %v\n", err)
		return
	}
	defer jsonContent.Close()

	encoder := json.NewEncoder(jsonContent)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(vulnResults); err != nil {
		fmt.Printf("[!] Error writing JSON file: %v\n", err)
		return
	}

	fmt.Printf("\n[+] Results saved to:\n    - %s\n    - %s\n", txtFile, jsonFile)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: clickjack_batch_fast.exe <url or urls.txt>")
		return
	}

	target := os.Args[1]

	// Check if it's a file
	if fileInfo, err := os.Stat(target); err == nil && !fileInfo.IsDir() {
		file, err := os.Open(target)
		if err != nil {
			fmt.Printf("[!] Error opening file: %v\n", err)
			return
		}
		defer file.Close()

		content, err := io.ReadAll(file)
		if err != nil {
			fmt.Printf("[!] Error reading file: %v\n", err)
			return
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				analyze(line)
			}
		}
	} else {
		analyze(target)
	}

	writeOutputs()
}