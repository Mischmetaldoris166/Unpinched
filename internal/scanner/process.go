package scanner

import (
	"io"
	"os"
	"strings"

	"github.com/shirou/gopsutil/v3/process"
)

// ProcessFinding captures a suspicious running process.
type ProcessFinding struct {
	PID         int32  `json:"pid"`
	Name        string `json:"name"`
	CmdLine     string `json:"cmd_line"`
	MatchReason string `json:"match_reason"`
	Confidence  string `json:"confidence"`
}

// targetProcessNames are the exact binary names (without extension) that indicate PinchTab is running.
var targetProcessNames = []string{
	"pinchtab",
	"pinchtab-server",
	"browser-bridge",
}

// stripExt removes a .exe suffix on Windows for normalised comparison.
func stripExt(name string) string {
	if strings.HasSuffix(name, ".exe") {
		return name[:len(name)-4]
	}
	return name
}

// ScanProcesses walks all running processes and returns suspicious findings.
func ScanProcesses() ([]ProcessFinding, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, err
	}

	var findings []ProcessFinding
	selfPID := int32(os.Getpid())

	for _, p := range procs {
		if p.Pid == selfPID {
			continue
		}

		name, _ := p.Name()
		cmdline, _ := p.Cmdline()

		nameLower := strings.ToLower(stripExt(name))
		cmdLower := strings.ToLower(cmdline)

		// 1. Exact process name match.
		for _, target := range targetProcessNames {
			if nameLower == target {
				findings = append(findings, ProcessFinding{
					PID:         p.Pid,
					Name:        name,
					CmdLine:     truncate(cmdline, 512),
					MatchReason: "process name matches known PinchTab binary: " + target,
					Confidence:  "HIGH",
				})
				goto nextProc
			}
		}

		// 2. Command line substring match.
		for _, target := range targetProcessNames {
			if strings.Contains(cmdLower, target) {
				findings = append(findings, ProcessFinding{
					PID:         p.Pid,
					Name:        name,
					CmdLine:     truncate(cmdline, 512),
					MatchReason: "command line references known PinchTab artifact: " + target,
					Confidence:  "HIGH",
				})
				goto nextProc
			}
		}

		// 3. Environment variable scan — catches renamed binaries that set PINCHTAB_* vars.
		{
			envs, err := p.Environ()
			if err == nil {
				for _, env := range envs {
					if strings.HasPrefix(strings.ToUpper(env), "PINCHTAB_") {
						key := strings.SplitN(env, "=", 2)[0]
						findings = append(findings, ProcessFinding{
							PID:         p.Pid,
							Name:        name,
							CmdLine:     truncate(cmdline, 512),
							MatchReason: "process has PinchTab environment variable: " + key,
							Confidence:  "HIGH",
						})
						goto nextProc
					}
				}
			}
		}

		// 4. CDP port 9222 listener — check and optionally upgrade via binary string scan.
		{
			conns, err := p.Connections()
			if err == nil {
				for _, c := range conns {
					if c.Laddr.Port == 9222 && c.Status == "LISTEN" {
						confidence := "MEDIUM"
						reason := "process listening on CDP port 9222"

						// Attempt binary string scan to upgrade confidence.
						if exePath, err := p.Exe(); err == nil && exePath != "" {
							if binaryContainsPinchTab(exePath) {
								confidence = "HIGH"
								reason = "process listening on CDP port 9222 with PinchTab strings in binary"
							}
						}

						findings = append(findings, ProcessFinding{
							PID:         p.Pid,
							Name:        name,
							CmdLine:     truncate(cmdline, 512),
							MatchReason: reason,
							Confidence:  confidence,
						})
						goto nextProc
					}
				}
			}
		}

	nextProc:
	}

	return findings, nil
}

// binaryContainsPinchTab reads the first 1 MB of a binary and checks for PinchTab strings.
func binaryContainsPinchTab(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 1<<20) // 1 MB
	n, err := io.ReadFull(f, buf)
	if err != nil && n == 0 {
		return false
	}

	lower := strings.ToLower(string(buf[:n]))
	for _, kw := range []string{"pinchtab", "browser-bridge", "pinch-tab"} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}
