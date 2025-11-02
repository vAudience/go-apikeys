// Package apikeys provides API key authentication and management middleware for Go applications.
//
// This file contains input validation functions following CODE_RULES.md standards.
package apikeys

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var (
	// emailRegex validates email format
	emailRegex = regexp.MustCompile(REGEX_EMAIL)
)

// ValidationErrors represents a collection of validation errors.
// This is used to return multiple validation errors at once.
type ValidationErrors struct {
	Errors []ValidationError `json:"errors"`
}

// ValidationError represents a single field validation error.
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

// Error implements the error interface.
func (v *ValidationErrors) Error() string {
	if len(v.Errors) == 0 {
		return "validation failed"
	}
	if len(v.Errors) == 1 {
		return fmt.Sprintf("validation failed: %s %s", v.Errors[0].Field, v.Errors[0].Message)
	}
	return fmt.Sprintf("validation failed: %d errors", len(v.Errors))
}

// Add adds a validation error to the collection.
func (v *ValidationErrors) Add(field, message string) {
	v.Errors = append(v.Errors, ValidationError{
		Field:   field,
		Message: message,
	})
}

// HasErrors returns true if there are any validation errors.
func (v *ValidationErrors) HasErrors() bool {
	return len(v.Errors) > 0
}

// ToError returns the ValidationErrors as an error if there are errors, nil otherwise.
func (v *ValidationErrors) ToError() error {
	if !v.HasErrors() {
		return nil
	}
	return v
}

// Unwrap implements error unwrapping for ValidationErrors.
// This allows errors.Is() to recognize ValidationErrors as ErrInvalidInput.
func (v *ValidationErrors) Unwrap() error {
	return ErrInvalidInput
}

// ValidateAPIKeyInfo validates an APIKeyInfo structure comprehensively.
// Returns nil if valid, ValidationErrors if invalid.
func ValidateAPIKeyInfo(info *APIKeyInfo) error {
	if info == nil {
		return NewValidationError("api_key_info", "cannot be nil")
	}

	errors := &ValidationErrors{}

	// Validate UserID (required)
	if info.UserID == "" {
		errors.Add(JSON_FIELD_USER_ID, "is required")
	} else if len(info.UserID) < MIN_USER_ID_LENGTH {
		errors.Add(JSON_FIELD_USER_ID, fmt.Sprintf("must be at least %d characters", MIN_USER_ID_LENGTH))
	} else if len(info.UserID) > MAX_USER_ID_LENGTH {
		errors.Add(JSON_FIELD_USER_ID, fmt.Sprintf("must be at most %d characters", MAX_USER_ID_LENGTH))
	}

	// Validate OrgID (required)
	if info.OrgID == "" {
		errors.Add(JSON_FIELD_ORG_ID, "is required")
	} else if len(info.OrgID) < MIN_ORG_ID_LENGTH {
		errors.Add(JSON_FIELD_ORG_ID, fmt.Sprintf("must be at least %d characters", MIN_ORG_ID_LENGTH))
	} else if len(info.OrgID) > MAX_ORG_ID_LENGTH {
		errors.Add(JSON_FIELD_ORG_ID, fmt.Sprintf("must be at most %d characters", MAX_ORG_ID_LENGTH))
	}

	// Validate Email (optional, but must be valid if provided)
	if info.Email != "" {
		if len(info.Email) < MIN_EMAIL_LENGTH {
			errors.Add(JSON_FIELD_EMAIL, fmt.Sprintf("must be at least %d characters", MIN_EMAIL_LENGTH))
		} else if len(info.Email) > MAX_EMAIL_LENGTH {
			errors.Add(JSON_FIELD_EMAIL, fmt.Sprintf("must be at most %d characters", MAX_EMAIL_LENGTH))
		} else if !emailRegex.MatchString(info.Email) {
			errors.Add(JSON_FIELD_EMAIL, "invalid email format")
		}
	}

	// Validate Name (optional, but check length if provided)
	if info.Name != "" {
		if len(info.Name) < MIN_NAME_LENGTH {
			errors.Add(JSON_FIELD_NAME, fmt.Sprintf("must be at least %d characters", MIN_NAME_LENGTH))
		} else if len(info.Name) > MAX_NAME_LENGTH {
			errors.Add(JSON_FIELD_NAME, fmt.Sprintf("must be at most %d characters", MAX_NAME_LENGTH))
		}
	}

	// Validate Metadata size (prevent huge payloads)
	if info.Metadata != nil {
		metadataJSON, err := json.Marshal(info.Metadata)
		if err != nil {
			errors.Add(JSON_FIELD_METADATA, "invalid JSON")
		} else if len(metadataJSON) > MAX_METADATA_SIZE {
			errors.Add(JSON_FIELD_METADATA, fmt.Sprintf("too large (max %d bytes)", MAX_METADATA_SIZE))
		}
	}

	// Validate Roles (ensure no empty strings)
	for i, role := range info.Roles {
		if strings.TrimSpace(role) == "" {
			errors.Add(JSON_FIELD_ROLES, fmt.Sprintf("role at index %d is empty", i))
		}
	}

	// Validate Rights (ensure no empty strings)
	for i, right := range info.Rights {
		if strings.TrimSpace(right) == "" {
			errors.Add(JSON_FIELD_RIGHTS, fmt.Sprintf("right at index %d is empty", i))
		}
	}

	return errors.ToError()
}

// ValidateConfig validates a Config structure.
// Returns nil if valid, error if invalid.
func ValidateConfig(config *Config) error {
	if config == nil {
		return NewValidationError("config", "cannot be nil")
	}

	errors := &ValidationErrors{}

	// Validate Repository (required)
	if config.Repository == nil {
		errors.Add("repository", "is required")
	}

	// Validate Framework (required)
	if config.Framework == nil {
		errors.Add("framework", "is required")
	}

	// Validate HeaderKey (required)
	if config.HeaderKey == "" {
		errors.Add("header_key", "is required")
	}

	// Validate ApiKeyPrefix (required)
	if config.ApiKeyPrefix == "" {
		errors.Add("api_key_prefix", "is required")
	} else if len(config.ApiKeyPrefix) < 2 || len(config.ApiKeyPrefix) > 5 {
		errors.Add("api_key_prefix", "must be 2-5 characters")
	} else {
		// Prefix must be lowercase letters only
		for _, char := range config.ApiKeyPrefix {
			if char < 'a' || char > 'z' {
				errors.Add("api_key_prefix", "must contain only lowercase letters")
				break
			}
		}
	}

	// Validate ApiKeyLength
	if config.ApiKeyLength < 10 {
		errors.Add("api_key_length", "must be at least 10")
	} else if config.ApiKeyLength > 100 {
		errors.Add("api_key_length", "must be at most 100 (recommended: 16-32)")
	}

	// Validate BootstrapConfig if bootstrap is enabled
	if config.EnableBootstrap {
		if config.BootstrapConfig == nil {
			errors.Add("bootstrap_config", "is required when bootstrap is enabled")
		} else {
			// Require explicit security acknowledgment
			if !config.BootstrapConfig.IUnderstandSecurityRisks {
				errors.Add("bootstrap_config.i_understand_security_risks",
					"must be true to enable bootstrap (acknowledges plain-text key logging)")
			}
			// Validate required fields
			if config.BootstrapConfig.AdminUserID == "" {
				errors.Add("bootstrap_config.admin_user_id", "is required")
			}
			if config.BootstrapConfig.AdminOrgID == "" {
				errors.Add("bootstrap_config.admin_org_id", "is required")
			}
		}
	}

	return errors.ToError()
}

// ValidateAPIKey validates an API key string format.
// Returns nil if valid, error if invalid.
func ValidateAPIKey(apiKey string) error {
	if apiKey == "" {
		return ErrAPIKeyRequired
	}

	if !IsAPIKey(apiKey) {
		return ErrInvalidAPIKey
	}

	return nil
}

// ValidateUserID validates a user ID.
// Returns nil if valid, error if invalid.
func ValidateUserID(userID string) error {
	if userID == "" {
		return ErrMissingUserID
	}

	if len(userID) < MIN_USER_ID_LENGTH {
		return NewValidationError(JSON_FIELD_USER_ID, fmt.Sprintf("must be at least %d characters", MIN_USER_ID_LENGTH))
	}

	if len(userID) > MAX_USER_ID_LENGTH {
		return NewValidationError(JSON_FIELD_USER_ID, fmt.Sprintf("must be at most %d characters", MAX_USER_ID_LENGTH))
	}

	return nil
}

// ValidateOrgID validates an organization ID.
// Returns nil if valid, error if invalid.
func ValidateOrgID(orgID string) error {
	if orgID == "" {
		return ErrMissingOrgID
	}

	if len(orgID) < MIN_ORG_ID_LENGTH {
		return NewValidationError(JSON_FIELD_ORG_ID, fmt.Sprintf("must be at least %d characters", MIN_ORG_ID_LENGTH))
	}

	if len(orgID) > MAX_ORG_ID_LENGTH {
		return NewValidationError(JSON_FIELD_ORG_ID, fmt.Sprintf("must be at most %d characters", MAX_ORG_ID_LENGTH))
	}

	return nil
}

// ValidateEmail validates an email address format.
// Returns nil if valid, error if invalid.
func ValidateEmail(email string) error {
	if email == "" {
		return nil // Email is optional
	}

	if len(email) < MIN_EMAIL_LENGTH {
		return NewValidationError(JSON_FIELD_EMAIL, fmt.Sprintf("must be at least %d characters", MIN_EMAIL_LENGTH))
	}

	if len(email) > MAX_EMAIL_LENGTH {
		return NewValidationError(JSON_FIELD_EMAIL, fmt.Sprintf("must be at most %d characters", MAX_EMAIL_LENGTH))
	}

	if !emailRegex.MatchString(email) {
		return NewValidationError(JSON_FIELD_EMAIL, "invalid email format")
	}

	return nil
}

// SanitizeString removes leading/trailing whitespace and limits length.
// This is useful for sanitizing user input before validation.
func SanitizeString(s string, maxLength int) string {
	s = strings.TrimSpace(s)
	if len(s) > maxLength {
		s = s[:maxLength]
	}
	return s
}

// SanitizeAPIKeyInfo sanitizes all string fields in APIKeyInfo.
// This should be called before validation to clean up user input.
func SanitizeAPIKeyInfo(info *APIKeyInfo) {
	if info == nil {
		return
	}

	info.UserID = SanitizeString(info.UserID, MAX_USER_ID_LENGTH)
	info.OrgID = SanitizeString(info.OrgID, MAX_ORG_ID_LENGTH)
	info.Name = SanitizeString(info.Name, MAX_NAME_LENGTH)
	info.Email = SanitizeString(info.Email, MAX_EMAIL_LENGTH)

	// Sanitize roles
	for i, role := range info.Roles {
		info.Roles[i] = strings.TrimSpace(role)
	}

	// Sanitize rights
	for i, right := range info.Rights {
		info.Rights[i] = strings.TrimSpace(right)
	}
}
