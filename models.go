// Package apikeys provides API key authentication and management middleware for Go applications.
package apikeys

// APIKeyInfo represents the complete information about an API key.
// This structure is used for both storage and API responses.
type APIKeyInfo struct {
	// APIKey is the plain-text API key (only populated on creation, never stored)
	APIKey string `json:"api_key,omitempty"`

	// APIKeyHash is the SHA3-512 hash of the API key (stored in repository)
	APIKeyHash string `json:"api_key_hash"`

	// APIKeyHint is a hint showing first/last characters (for user reference)
	APIKeyHint string `json:"api_key_hint"`

	// UserID identifies the user this API key belongs to (required)
	UserID string `json:"user_id"`

	// OrgID identifies the organization this API key belongs to (required)
	OrgID string `json:"org_id"`

	// Name is an optional human-readable name for the API key
	Name string `json:"name,omitempty"`

	// Email is the email address associated with this API key (optional)
	Email string `json:"email,omitempty"`

	// Roles contains the role names assigned to this API key
	Roles []string `json:"roles,omitempty"`

	// Rights contains specific permission strings
	Rights []string `json:"rights,omitempty"`

	// Metadata contains arbitrary key-value data (e.g., system_admin flag)
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Filter creates a filtered copy of APIKeyInfo for API responses.
// Use this to control whether sensitive data is included in responses.
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

// String returns the API key hash as the string representation.
// This is safe to log and display.
func (a APIKeyInfo) String() string {
	return a.APIKeyHash
}
