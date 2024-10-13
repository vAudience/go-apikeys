package apikeys

import (
	"errors"
	"regexp"
	"time"

	"github.com/itsatony/go-datarepository"
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

func (a APIKeyInfo) String() string {
	return a.APIKeyHash
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

const (
	LOCALS_KEY_APIKEYS                    = "apikey"
	ERROR_INVALID_API_KEY                 = "invalid API key"
	ERROR_FAILED_TO_RETRIEVE_API_KEY_INFO = "failed to retrieve API key information"
	ERROR_FAILED_TO_CHECK_RATE_LIMIT      = "failed to check rate limit"
	ERROR_RATE_LIMIT_EXCEEDED             = "rate limit exceeded"
	METADATA_KEYS_SYSTEM_ADMIN            = "systemadmin"
)

var (
	APIKEY_RANDOMSTRING_LENGTH = 32
	APIKEY_PREFIX              = "gak_"
)

var (
	ErrInvalidAPIKey              = errors.New(ERROR_INVALID_API_KEY)
	ErrFailedToRetrieveAPIKeyInfo = errors.New(ERROR_FAILED_TO_RETRIEVE_API_KEY_INFO)
	ErrFailedToCheckRateLimit     = errors.New(ERROR_FAILED_TO_CHECK_RATE_LIMIT)
	ErrRateLimitExceeded          = errors.New(ERROR_RATE_LIMIT_EXCEEDED)
	ErrAPIKeyNotFound             = datarepository.ErrNotFound
)

// Helper functions to check error types
func IsNotFoundError(err error) bool {
	return datarepository.IsNotFoundError(err)
}

func IsAlreadyExistsError(err error) bool {
	return datarepository.IsAlreadyExistsError(err)
}

func IsInvalidIdentifierError(err error) bool {
	return datarepository.IsInvalidIdentifierError(err)
}

func IsInvalidInputError(err error) bool {
	return datarepository.IsInvalidInputError(err)
}

func IsOperationFailedError(err error) bool {
	return datarepository.IsOperationFailedError(err)
}
