package scanner

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// ConfigFinding captures a PinchTab token, config, log, or PID artifact.
type ConfigFinding struct {
	Path       string `json:"path"`       // file path or "env:VAR_NAME"
	Type       string `json:"type"`       // "config_dir"|"token_file"|"log_file"|"pid_file"|"env_var"
	TokenFound bool   `json:"token_found"`
	TokenHint  string `json:"token_hint,omitempty"` // first 8 chars + "****"
	Confidence string `json:"confidence"`
}

// tokenPattern matches PinchTab API tokens of the form pt_<16+ alnum chars>.
var tokenPattern = regexp.MustCompile(`pt_[A-Za-z0-9_\-]{16,}`)

// ScanConfig checks for PinchTab token/config/log/PID artifacts and env vars.
func ScanConfig() []ConfigFinding {
	var findings []ConfigFinding
	home, _ := os.UserHomeDir()

	findings = append(findings, scanConfigDirs(home)...)
	findings = append(findings, scanTokenFiles(home)...)
	findings = append(findings, scanLogFiles(home)...)
	findings = append(findings, scanPIDFiles()...)
	findings = append(findings, scanEnvVars()...)

	return findings
}

// --- Config directories ---

func scanConfigDirs(home string) []ConfigFinding {
	dirs := configDirPaths(home)
	var findings []ConfigFinding
	for _, d := range dirs {
		info, err := os.Stat(d)
		if err != nil || !info.IsDir() {
			continue
		}
		findings = append(findings, ConfigFinding{
			Path:       d,
			Type:       "config_dir",
			Confidence: "MEDIUM",
		})
	}
	return findings
}

func configDirPaths(home string) []string {
	paths := []string{}
	if home != "" {
		paths = append(paths,
			filepath.Join(home, ".pinchtab"),
			filepath.Join(home, ".config", "pinchtab"),
		)
	}
	switch runtime.GOOS {
	case "darwin":
		if home != "" {
			paths = append(paths, filepath.Join(home, "Library", "Application Support", "pinchtab"))
		}
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			paths = append(paths, filepath.Join(appdata, "pinchtab"))
		}
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			paths = append(paths, filepath.Join(local, "pinchtab"))
		}
	}
	return paths
}

// --- Token/key files ---

func scanTokenFiles(home string) []ConfigFinding {
	candidates := tokenFilePaths(home)
	var findings []ConfigFinding
	for _, p := range candidates {
		if f := probeTokenFile(p); f.Path != "" {
			findings = append(findings, f)
		}
	}
	return findings
}

func tokenFilePaths(home string) []string {
	paths := []string{}
	if home != "" {
		paths = append(paths,
			filepath.Join(home, ".pinchtab.token"),
			filepath.Join(home, ".pinchtab.key"),
			filepath.Join(home, ".pinchtab.json"),
			filepath.Join(home, ".config", "pinchtab", "token"),
			filepath.Join(home, ".config", "pinchtab", "config.json"),
		)
	}
	// /tmp glob
	if matches, err := filepath.Glob("/tmp/pinchtab*.token"); err == nil {
		paths = append(paths, matches...)
	}
	if matches, err := filepath.Glob("/tmp/pinchtab*.json"); err == nil {
		paths = append(paths, matches...)
	}
	return paths
}

func probeTokenFile(path string) ConfigFinding {
	data, err := os.ReadFile(path)
	if err != nil {
		return ConfigFinding{}
	}
	f := ConfigFinding{
		Path:       path,
		Type:       "token_file",
		Confidence: "HIGH",
	}
	content := string(data)
	if m := tokenPattern.FindString(content); m != "" {
		f.TokenFound = true
		hint := m
		if len(hint) > 8 {
			hint = hint[:8] + "****"
		}
		f.TokenHint = hint
	}
	return f
}

// --- Log files ---

func scanLogFiles(home string) []ConfigFinding {
	candidates := logFilePaths(home)
	var findings []ConfigFinding
	for _, p := range candidates {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if info.IsDir() {
			// Check if the log directory is non-empty.
			entries, _ := os.ReadDir(p)
			if len(entries) == 0 {
				continue
			}
		} else if info.Size() == 0 {
			continue
		}
		findings = append(findings, ConfigFinding{
			Path:       p,
			Type:       "log_file",
			Confidence: "LOW",
		})
	}
	return findings
}

func logFilePaths(home string) []string {
	paths := []string{
		"/var/log/pinchtab",
	}
	if home != "" {
		paths = append(paths, filepath.Join(home, ".pinchtab", "logs"))
	}
	if matches, err := filepath.Glob("/var/log/pinchtab*"); err == nil {
		paths = append(paths, matches...)
	}
	if runtime.GOOS == "darwin" && home != "" {
		paths = append(paths, filepath.Join(home, "Library", "Logs", "pinchtab"))
		if matches, err := filepath.Glob(filepath.Join(home, "Library", "Logs", "pinchtab*")); err == nil {
			paths = append(paths, matches...)
		}
	}
	return paths
}

// --- Lock / PID files ---

func scanPIDFiles() []ConfigFinding {
	candidates := pidFilePaths()
	var findings []ConfigFinding
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			findings = append(findings, ConfigFinding{
				Path:       p,
				Type:       "pid_file",
				Confidence: "MEDIUM",
			})
		}
	}
	return findings
}

func pidFilePaths() []string {
	paths := []string{
		"/var/run/pinchtab.pid",
		"/var/lock/pinchtab.lock",
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		paths = append(paths,
			filepath.Join(home, ".local", "share", "pinchtab", "pinchtab.pid"),
		)
	}
	if matches, err := filepath.Glob("/tmp/pinchtab*.pid"); err == nil {
		paths = append(paths, matches...)
	}
	return paths
}

// --- Environment variables ---

func scanEnvVars() []ConfigFinding {
	var findings []ConfigFinding
	for _, env := range os.Environ() {
		parts := strings.SplitN(env, "=", 2)
		key := parts[0]
		if strings.HasPrefix(strings.ToUpper(key), "PINCHTAB_") {
			val := ""
			if len(parts) == 2 {
				val = parts[1]
			}
			f := ConfigFinding{
				Path:       "env:" + key,
				Type:       "env_var",
				Confidence: "HIGH",
			}
			if m := tokenPattern.FindString(val); m != "" {
				f.TokenFound = true
				hint := m
				if len(hint) > 8 {
					hint = hint[:8] + "****"
				}
				f.TokenHint = hint
			}
			findings = append(findings, f)
		}
	}
	return findings
}
