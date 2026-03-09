package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/helixar-ai/pinchtab-detector/internal/scanner"
)

const version = "v0.2.0"

// ScanReport aggregates all detection findings.
type ScanReport struct {
	Timestamp          time.Time                   `json:"timestamp"`
	Hostname           string                      `json:"hostname"`
	OS                 string                      `json:"os"`
	RiskLevel          string                      `json:"risk_level"`
	Summary            string                      `json:"summary"`
	PortFindings       []scanner.PortFinding       `json:"port_findings"`
	ProcessFindings    []scanner.ProcessFinding    `json:"process_findings"`
	CDPFindings        []scanner.CDPFinding        `json:"cdp_findings"`
	FilesystemFindings []scanner.FilesystemFinding `json:"filesystem_findings"`
	ConfigFindings     []scanner.ConfigFinding     `json:"config_findings"`
	PersistFindings    []scanner.PersistFinding    `json:"persist_findings"`
}

// ComputeRiskLevel derives the overall risk level from all findings.
func ComputeRiskLevel(r *ScanReport) string {
	hasSigPort := false
	hasAuthPort := false
	hasOpenPort := false
	hasProcess := false
	hasFS := false
	hasCDP := false
	hasToken := false
	hasConfigDir := false
	hasPersist := false
	hasEnvVar := false

	for _, f := range r.PortFindings {
		if f.Open && f.Signature {
			hasSigPort = true
		} else if f.Open && f.AuthGated {
			hasAuthPort = true
		} else if f.Open {
			hasOpenPort = true
		}
	}
	for range r.ProcessFindings {
		hasProcess = true
	}
	for range r.FilesystemFindings {
		hasFS = true
	}
	for _, f := range r.CDPFindings {
		if f.CDPOpen {
			hasCDP = true
		}
	}
	for _, f := range r.ConfigFindings {
		if f.TokenFound || f.Type == "env_var" {
			hasEnvVar = true
		}
		if f.Type == "token_file" {
			hasToken = true
		}
		if f.Type == "config_dir" {
			hasConfigDir = true
		}
	}
	for range r.PersistFindings {
		hasPersist = true
	}

	switch {
	case hasToken && (hasSigPort || hasAuthPort || hasOpenPort || hasCDP):
		return "CRITICAL"
	case hasSigPort && hasCDP:
		return "CRITICAL"
	case hasToken || hasEnvVar:
		return "HIGH"
	case hasProcess && (hasOpenPort || hasSigPort || hasAuthPort):
		return "HIGH"
	case hasFS && (hasOpenPort || hasSigPort || hasAuthPort):
		return "HIGH"
	case hasProcess || hasSigPort || hasPersist:
		return "HIGH"
	case hasAuthPort || hasOpenPort || hasCDP || hasConfigDir:
		return "MEDIUM"
	case hasFS:
		return "LOW"
	default:
		return "NONE"
	}
}

// BuildSummary returns a human-readable summary for the risk level.
func BuildSummary(r *ScanReport) string {
	switch r.RiskLevel {
	case "CRITICAL":
		return "Active PinchTab deployment confirmed — token and live service both detected. Immediate investigation required."
	case "HIGH":
		return "Strong indicators of PinchTab deployment found. Review findings below."
	case "MEDIUM":
		return "Suspicious artifacts detected. PinchTab not confirmed but environment is at risk."
	case "LOW":
		return "PinchTab filesystem artifacts found. No active service detected."
	default:
		return "No PinchTab indicators found on this host."
	}
}

// PrintText renders a coloured human-readable report to stdout.
func PrintText(r *ScanReport, noColor bool) {
	if noColor {
		color.NoColor = true
	}

	bold := color.New(color.Bold)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	red := color.New(color.FgRed)
	cyan := color.New(color.FgCyan)

	divider := strings.Repeat("━", 52)

	bold.Printf("\npinchtab-detector %s — Helixar Labs\n", version)
	cyan.Printf("Scanning host: %s (%s)\n", r.Hostname, r.OS)
	fmt.Println(divider)

	// PORT SCAN
	if len(r.PortFindings) == 0 {
		green.Println("[PORT SCAN]      ✓ No PinchTab HTTP API detected on common ports")
	} else {
		for _, f := range r.PortFindings {
			switch {
			case f.Signature:
				red.Printf("[PORT SCAN]      ✗ PinchTab signature on port %d [%s]\n", f.Port, f.Confidence)
			case f.AuthGated:
				yellow.Printf("[PORT SCAN]      ⚠ Auth-protected service on port %d — possible token-gated PinchTab API [%s]\n", f.Port, f.Confidence)
			default:
				yellow.Printf("[PORT SCAN]      ⚠ Port %d open — no PinchTab signature [%s]\n", f.Port, f.Confidence)
			}
		}
	}

	// PROCESS SCAN
	if len(r.ProcessFindings) == 0 {
		green.Println("[PROCESS SCAN]   ✓ No PinchTab process found")
	} else {
		for _, f := range r.ProcessFindings {
			red.Printf("[PROCESS SCAN]   ✗ %s (PID %d) — %s [%s]\n", f.Name, f.PID, f.MatchReason, f.Confidence)
		}
	}

	// CDP BRIDGE
	hasCDP := false
	for _, f := range r.CDPFindings {
		if f.CDPOpen {
			hasCDP = true
			if f.Confidence == "HIGH" {
				yellow.Printf("[CDP BRIDGE]     ⚠ Chrome DevTools Protocol exposed on :9222 (no auth) — %s\n", f.BrowserVersion)
			} else {
				yellow.Println("[CDP BRIDGE]     ⚠ Port 9222 open — unknown service, possible CDP")
			}
		}
	}
	if !hasCDP {
		green.Println("[CDP BRIDGE]     ✓ CDP not exposed on :9222")
	}

	// FILESYSTEM
	if len(r.FilesystemFindings) == 0 {
		green.Println("[FILESYSTEM]     ✓ No PinchTab binary artifacts found")
	} else {
		for _, f := range r.FilesystemFindings {
			if f.Executable {
				red.Printf("[FILESYSTEM]     ✗ Executable: %s (%d bytes) [%s]\n", f.Path, f.Size, f.Confidence)
			} else {
				yellow.Printf("[FILESYSTEM]     ⚠ Artifact: %s (%d bytes) [%s]\n", f.Path, f.Size, f.Confidence)
			}
		}
	}

	// CONFIG / TOKEN
	if len(r.ConfigFindings) == 0 {
		green.Println("[CONFIG/TOKEN]   ✓ No token, config, or env var artifacts found")
	} else {
		for _, f := range r.ConfigFindings {
			switch f.Type {
			case "token_file":
				if f.TokenFound {
					red.Printf("[CONFIG/TOKEN]   ✗ Token file with valid token: %s (%s…) [%s]\n", f.Path, f.TokenHint, f.Confidence)
				} else {
					yellow.Printf("[CONFIG/TOKEN]   ⚠ Token file found: %s [%s]\n", f.Path, f.Confidence)
				}
			case "env_var":
				if f.TokenFound {
					red.Printf("[CONFIG/TOKEN]   ✗ PinchTab env var with token: %s (%s…) [%s]\n", f.Path, f.TokenHint, f.Confidence)
				} else {
					red.Printf("[CONFIG/TOKEN]   ✗ PinchTab env var set: %s [%s]\n", f.Path, f.Confidence)
				}
			case "config_dir":
				yellow.Printf("[CONFIG/TOKEN]   ⚠ PinchTab config directory exists: %s [%s]\n", f.Path, f.Confidence)
			case "log_file":
				yellow.Printf("[CONFIG/TOKEN]   ⚠ PinchTab log artifact: %s [%s]\n", f.Path, f.Confidence)
			case "pid_file":
				yellow.Printf("[CONFIG/TOKEN]   ⚠ PinchTab PID/lock file: %s [%s]\n", f.Path, f.Confidence)
			}
		}
	}

	// PERSISTENCE
	if len(r.PersistFindings) == 0 {
		green.Println("[PERSISTENCE]    ✓ No launchd, systemd, or Chrome extension artifacts found")
	} else {
		for _, f := range r.PersistFindings {
			red.Printf("[PERSISTENCE]    ✗ %s artifact: %s [%s]\n", strings.ToUpper(f.Type), f.Path, f.Confidence)
			if f.Content != "" {
				fmt.Printf("                  → %s\n", truncateStr(f.Content, 80))
			}
		}
	}

	fmt.Println(divider)

	// Risk level banner
	switch r.RiskLevel {
	case "CRITICAL", "HIGH":
		red.Printf("RISK LEVEL: %s\n", r.RiskLevel)
		red.Println(r.Summary)
	case "MEDIUM":
		yellow.Printf("RISK LEVEL: %s\n", r.RiskLevel)
		yellow.Println(r.Summary)
	case "LOW":
		yellow.Printf("RISK LEVEL: %s\n", r.RiskLevel)
		fmt.Println(r.Summary)
	default:
		green.Printf("RISK LEVEL: %s\n", r.RiskLevel)
		green.Println(r.Summary)
	}

	if r.RiskLevel != "NONE" {
		fmt.Println()
		cyan.Println("For continuous agentic threat detection without pre-written rules → helixar.ai")
	}
	fmt.Println()
}

// PrintJSON renders the report as machine-readable JSON to stdout.
func PrintJSON(r *ScanReport) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
