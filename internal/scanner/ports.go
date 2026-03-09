package scanner

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// PortFinding captures the result of a single port probe.
type PortFinding struct {
	Port       int    `json:"port"`
	Open       bool   `json:"open"`
	Signature  bool   `json:"signature"`
	AuthGated  bool   `json:"auth_gated"`  // true if 401/403 — auth-protected service on a PinchTab port
	Response   string `json:"response"`
	Confidence string `json:"confidence"`
}

// defaultPorts are the ports checked unless overridden by --ports.
// Expanded to include common alt ports for Node/Python HTTP servers.
var defaultPorts = []int{
	3000, 4000, 5000, 5001,
	6000, 7000, 7001,
	8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090,
	9222, 9229,
}

// signatureStrings are substrings that indicate a PinchTab HTTP API response body.
var signatureStrings = []string{
	"pinchtab",
	"browser-bridge",
	"orchestrator",
	"helixar",
}

// signatureHeaders are HTTP response headers whose values indicate PinchTab.
var signatureHeaders = []string{
	"x-pinchtab",
	"x-browser-bridge",
}

// ScanPorts probes each port and returns all open findings.
func ScanPorts(extraPorts []int, timeout time.Duration) []PortFinding {
	ports := dedupe(append(defaultPorts, extraPorts...))
	findings := make([]PortFinding, 0, len(ports))

	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse // don't follow redirects
		},
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: timeout}).DialContext,
		},
	}

	for _, port := range ports {
		finding := probePort(client, port, timeout)
		if finding.Open {
			findings = append(findings, finding)
		}
	}
	return findings
}

func probePort(client *http.Client, port int, timeout time.Duration) PortFinding {
	f := PortFinding{Port: port, Confidence: "LOW"}

	// TCP dial to check if port is open at all.
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), timeout)
	if err != nil {
		return f // port closed
	}
	conn.Close()
	f.Open = true
	f.Confidence = "MEDIUM"

	// HTTP probe on common status endpoints.
	for _, path := range []string{"/api/status", "/status", "/"} {
		url := fmt.Sprintf("http://127.0.0.1:%d%s", port, path)
		resp, err := client.Get(url) //nolint:noctx
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		// --- Header fingerprinting ---

		// Server header
		serverHeader := strings.ToLower(resp.Header.Get("Server"))
		for _, sig := range signatureStrings {
			if strings.Contains(serverHeader, sig) {
				f.Signature = true
				f.Confidence = "HIGH"
				f.Response = "Server header: " + resp.Header.Get("Server")
				return f
			}
		}

		// Custom PinchTab headers
		for _, hdr := range signatureHeaders {
			if resp.Header.Get(hdr) != "" {
				f.Signature = true
				f.Confidence = "HIGH"
				f.Response = hdr + ": " + resp.Header.Get(hdr)
				return f
			}
		}

		// --- Auth-gated detection (token-protected API) ---
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			f.AuthGated = true
			// Check WWW-Authenticate realm for PinchTab signature.
			wwwAuth := strings.ToLower(resp.Header.Get("WWW-Authenticate"))
			for _, sig := range signatureStrings {
				if strings.Contains(wwwAuth, sig) {
					f.Signature = true
					f.Confidence = "HIGH"
					f.Response = "WWW-Authenticate: " + resp.Header.Get("WWW-Authenticate")
					return f
				}
			}
			// Auth-protected on a PinchTab default port — flag as MEDIUM if not already higher.
			if f.Confidence != "HIGH" {
				f.Confidence = "MEDIUM"
				f.Response = fmt.Sprintf("HTTP %d on port %d — auth-protected service", resp.StatusCode, port)
			}
			return f
		}

		// --- Body signature check ---
		bodyStr := strings.ToLower(string(body))
		for _, sig := range signatureStrings {
			if strings.Contains(bodyStr, sig) {
				f.Signature = true
				f.Confidence = "HIGH"
				f.Response = truncate(string(body), 256)
				return f
			}
		}

		if f.Response == "" && len(body) > 0 {
			f.Response = truncate(string(body), 256)
		}
	}
	return f
}

func dedupe(ports []int) []int {
	seen := make(map[int]struct{}, len(ports))
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
