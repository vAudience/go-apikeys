// Package apikeys provides API key authentication and management middleware for Go applications.
//
// This file handles version management using go-version.
package apikeys

import (
	"embed"
	"sync"

	goversion "github.com/itsatony/go-version"
	"go.uber.org/zap"
)

//go:embed versions.yaml
var versionsFS embed.FS

var (
	versionInitOnce sync.Once
	versionInitErr  error
)

// InitializeVersion initializes the go-version package with our versions.yaml
func InitializeVersion() error {
	versionInitOnce.Do(func() {
		// Read versions.yaml from embedded FS
		data, err := versionsFS.ReadFile("versions.yaml")
		if err != nil {
			versionInitErr = NewInternalError("version_init_read", err)
			return
		}

		// Initialize go-version with embedded manifest data
		versionInitErr = goversion.Initialize(
			goversion.WithEmbedded(data),
		)
	})

	return versionInitErr
}

// GetProjectVersion returns the current project version
func GetProjectVersion() string {
	// Ensure initialized
	if err := InitializeVersion(); err != nil {
		return PACKAGE_VERSION // Fallback to constant
	}

	info, err := goversion.Get()
	if err != nil {
		return PACKAGE_VERSION
	}
	return info.Project.Version
}

// GetAPIVersion returns the API version
func GetAPIVersion(apiName string) string {
	if err := InitializeVersion(); err != nil {
		return "1.0.0" // Fallback
	}

	info, err := goversion.Get()
	if err != nil {
		return "1.0.0"
	}

	if ver, ok := info.GetAPIVersion(apiName); ok {
		return ver
	}
	return "1.0.0"
}

// GetComponentVersion returns a component version
func GetComponentVersion(componentName string) string {
	if err := InitializeVersion(); err != nil {
		return "unknown" // Fallback
	}

	info, err := goversion.Get()
	if err != nil {
		return "unknown"
	}

	if ver, ok := info.GetComponentVersion(componentName); ok {
		return ver
	}
	return "unknown"
}

// LogVersionInfo logs version information at startup
func LogVersionInfo(logger *zap.Logger) {
	if err := InitializeVersion(); err != nil {
		logger.Warn("Failed to initialize version",
			zap.Error(err),
			zap.String("fallback_version", PACKAGE_VERSION))
		return
	}

	info, err := goversion.Get()
	if err != nil {
		logger.Warn("Failed to get version info",
			zap.Error(err),
			zap.String("fallback_version", PACKAGE_VERSION))
		return
	}

	// Use the LogFields() method from go-version Info
	fields := info.LogFields()
	logger.Info("Version information loaded", fields...)
}
