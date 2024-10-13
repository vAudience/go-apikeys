// github.com/vaudience/go-apikeys/config.go
package apikeys

import "github.com/itsatony/go-datarepository"

type Config struct {
	HeaderKey                    string
	ApiKeyPrefix                 string
	ApiKeyLength                 int
	IgnoreApiKeyForRoutePatterns []string
	Repository                   datarepository.DataRepository
	SystemAPIKey                 string
	EnableCRUD                   bool
	EnableRateLimit              bool
	RateLimitRules               []RateLimitRule
	Logger                       LogAdapter
	Framework                    HTTPFramework
}
