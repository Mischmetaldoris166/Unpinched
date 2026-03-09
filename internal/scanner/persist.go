package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// PersistFinding captures a PinchTab persistence or Chrome extension artifact.
type PersistFinding struct {
	Path       string `json:"path"`
	Type       string `json:"type"`    // "launchd"|"systemd"|"chrome_extension"
	Content    string `json:"content"` // truncated relevant excerpt
	Confidence string `json:"confidence"`
}

// ScanPersist checks for PinchTab launchd/systemd persistence and Chrome extension artifacts.
func ScanPersist() []PersistFinding {
	var findings []PersistFinding

	switch runtime.GOOS {
	case "darwin":
		findings = append(findings, scanLaunchd()...)
	case "linux":
		findings = append(findings, scanSystemd()...)
	}

	findings = append(findings, scanChromeExtensions()...)
	return findings
}

// --- macOS launchd ---

func scanLaunchd() []PersistFinding {
	home, _ := os.UserHomeDir()
	dirs := []string{
		"/Library/LaunchDaemons",
		"/Library/LaunchAgents",
	}
	if home != "" {
		dirs = append(dirs, filepath.Join(home, "Library", "LaunchAgents"))
	}

	var findings []PersistFinding
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := strings.ToLower(e.Name())
			path := filepath.Join(dir, e.Name())

			if containsAny(name, pinchtabKeywords) {
				findings = append(findings, PersistFinding{
					Path:       path,
					Type:       "launchd",
					Content:    "filename matches PinchTab artifact: " + e.Name(),
					Confidence: "HIGH",
				})
				continue
			}

			// Read content and check for keywords.
			if excerpt := grepFile(path, pinchtabKeywords, 512); excerpt != "" {
				findings = append(findings, PersistFinding{
					Path:       path,
					Type:       "launchd",
					Content:    truncate(excerpt, 256),
					Confidence: "HIGH",
				})
			}
		}
	}
	return findings
}

// --- Linux systemd ---

func scanSystemd() []PersistFinding {
	home, _ := os.UserHomeDir()
	dirs := []string{
		"/etc/systemd/system",
		"/usr/lib/systemd/system",
	}
	if home != "" {
		dirs = append(dirs, filepath.Join(home, ".config", "systemd", "user"))
	}

	var findings []PersistFinding
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := strings.ToLower(e.Name())
			path := filepath.Join(dir, e.Name())

			if containsAny(name, pinchtabKeywords) {
				findings = append(findings, PersistFinding{
					Path:       path,
					Type:       "systemd",
					Content:    "filename matches PinchTab artifact: " + e.Name(),
					Confidence: "HIGH",
				})
				continue
			}

			if excerpt := grepFile(path, pinchtabKeywords, 512); excerpt != "" {
				findings = append(findings, PersistFinding{
					Path:       path,
					Type:       "systemd",
					Content:    truncate(excerpt, 256),
					Confidence: "HIGH",
				})
			}
		}
	}
	return findings
}

// --- Chrome extensions ---

type chromeManifest struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

func scanChromeExtensions() []PersistFinding {
	dirs := chromeExtensionDirs()
	var findings []PersistFinding

	for _, base := range dirs {
		// Each subdirectory is an extension ID; inside is a version directory containing manifest.json.
		extDirs, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, extDir := range extDirs {
			if !extDir.IsDir() {
				continue
			}
			extPath := filepath.Join(base, extDir.Name())
			// Walk one level deep for version dirs.
			versionDirs, err := os.ReadDir(extPath)
			if err != nil {
				continue
			}
			for _, vDir := range versionDirs {
				if !vDir.IsDir() {
					continue
				}
				manifestPath := filepath.Join(extPath, vDir.Name(), "manifest.json")
				if f := probeManifest(manifestPath); f.Path != "" {
					findings = append(findings, f)
				}
			}
		}
	}
	return findings
}

func probeManifest(path string) PersistFinding {
	data, err := os.ReadFile(path)
	if err != nil {
		return PersistFinding{}
	}

	var m chromeManifest
	_ = json.Unmarshal(data, &m)

	combined := strings.ToLower(m.Name + " " + m.Description + " " + strings.Join(m.Permissions, " "))
	if containsAny(combined, pinchtabKeywords) {
		return PersistFinding{
			Path:       path,
			Type:       "chrome_extension",
			Content:    truncate("name="+m.Name+" desc="+m.Description, 256),
			Confidence: "HIGH",
		}
	}

	// Also raw-scan manifest bytes for keywords.
	if containsAny(strings.ToLower(string(data)), pinchtabKeywords) {
		return PersistFinding{
			Path:       path,
			Type:       "chrome_extension",
			Content:    "manifest content references PinchTab keyword",
			Confidence: "HIGH",
		}
	}

	return PersistFinding{}
}

func chromeExtensionDirs() []string {
	home, _ := os.UserHomeDir()
	var dirs []string

	switch runtime.GOOS {
	case "darwin":
		if home != "" {
			dirs = append(dirs,
				filepath.Join(home, "Library", "Application Support", "Google", "Chrome", "Default", "Extensions"),
				filepath.Join(home, "Library", "Application Support", "Chromium", "Default", "Extensions"),
			)
		}
	case "linux":
		if home != "" {
			dirs = append(dirs,
				filepath.Join(home, ".config", "google-chrome", "Default", "Extensions"),
				filepath.Join(home, ".config", "chromium", "Default", "Extensions"),
			)
		}
	case "windows":
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			dirs = append(dirs,
				filepath.Join(local, "Google", "Chrome", "User Data", "Default", "Extensions"),
				filepath.Join(local, "Chromium", "User Data", "Default", "Extensions"),
			)
		}
	}
	return dirs
}

// --- helpers ---

var pinchtabKeywords = []string{"pinchtab", "browser-bridge", "pinch-tab"}

func containsAny(s string, keywords []string) bool {
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// grepFile reads up to maxBytes of a file and returns the first line containing a keyword.
func grepFile(path string, keywords []string, maxBytes int64) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	buf := make([]byte, maxBytes)
	n, _ := f.Read(buf)
	content := strings.ToLower(string(buf[:n]))

	for _, kw := range keywords {
		if idx := strings.Index(content, kw); idx != -1 {
			start := idx - 40
			if start < 0 {
				start = 0
			}
			end := idx + len(kw) + 40
			if end > len(content) {
				end = len(content)
			}
			return content[start:end]
		}
	}
	return ""
}
