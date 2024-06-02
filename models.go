package apikeys

import (
	"regexp"
	"time"
)

type APIKeyInfo struct {
	APIKey   string         `json:"api_key"`
	UserID   string         `json:"user_id"`
	OrgID    string         `json:"org_id"`
	Name     string         `json:"name"`
	Email    string         `json:"email"`
	Roles    []string       `json:"roles"`
	Rights   []string       `json:"rights"`
	Metadata map[string]any `json:"metadata"`
}

type RateLimitRule struct {
	Path      string
	Timespan  time.Duration
	Limit     int
	ApplyTo   []RateLimitRuleTarget
	pathRegex *regexp.Regexp
}
