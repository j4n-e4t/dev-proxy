package config

import (
	"os"
	"path/filepath"
	"runtime"
)

// DefaultGlobalConfigPath returns the default location for the global config.
//
// On Windows we avoid "~" and a hard home-dir dependency because some environments
// don't provide one; we prefer os.UserConfigDir and fall back to os.TempDir.
//
// On Unix-y platforms we keep the historical default for back-compat.
func DefaultGlobalConfigPath() string {
	if runtime.GOOS == "windows" {
		if dir, err := os.UserConfigDir(); err == nil && dir != "" {
			return filepath.Join(dir, "dev-proxy", "config.yaml")
		}
		return filepath.Join(os.TempDir(), "dev-proxy", "config.yaml")
	}
	return "~/.dev-proxy.yaml"
}

