package apikeys

import (
	"regexp"
	"time"
)

type APIKeyInfo struct {
	APIKey     string         `json:"api_key"`
	APIKeyHash string         `json:"api_key_hash"`
	APIKeyHint string         `json:"api_key_hint"`
	UserID     string         `json:"user_id"`
	OrgID      string         `json:"org_id"`
	Name       string         `json:"name"`
	Email      string         `json:"email"`
	Roles      []string       `json:"roles"`
	Rights     []string       `json:"rights"`
	Metadata   map[string]any `json:"metadata"`
}

func (apikey *APIKeyInfo) Filter(includeSource bool, includeHash bool) *APIKeyInfo {
	carbonCopy := *apikey
	if !includeSource {
		carbonCopy.APIKey = ""
	}
	if !includeHash {
		carbonCopy.APIKeyHash = ""
	}
	return &carbonCopy
}

type RateLimitRule struct {
	Path      string
	Timespan  time.Duration
	Limit     int
	ApplyTo   []RateLimitRuleTarget
	pathRegex *regexp.Regexp
}

func emptyLogger(logLevel string, logContent string) {}

type LogAdapter func(logLevel string, logContent string)
