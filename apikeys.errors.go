// Package apikeys provides API key authentication and management middleware for Go applications.
//
// This file defines all error types and sentinel errors using go-cuserr.
// Integrated with go-cuserr v0.3.0 for consistent error handling across vAudience.AI services.
package apikeys

import (
	"errors"
	"fmt"

	"github.com/itsatony/go-cuserr"
)

// Sentinel errors using go-cuserr
// These are the base error types that can be wrapped with context
var (
	// ErrNotFound indicates a resource was not found (404, NOT_FOUND)
	ErrNotFound = cuserr.ErrNotFound

	// ErrAlreadyExists indicates a resource already exists (409, ALREADY_EXISTS)
	ErrAlreadyExists = errors.New("already exists")

	// ErrInvalidInput indicates invalid input data (400, INVALID_ARGUMENT)
	ErrInvalidInput = errors.New("invalid input")

	// ErrUnauthorized indicates authentication failure (401, UNAUTHENTICATED)
	ErrUnauthorized = errors.New("unauthorized")

	// ErrForbidden indicates authorization failure (403, PERMISSION_DENIED)
	ErrForbidden = errors.New("forbidden")

	// ErrInternal indicates an internal error (500, INTERNAL)
	ErrInternal = errors.New("internal error")

	// ErrTimeout indicates a timeout occurred (408, DEADLINE_EXCEEDED)
	ErrTimeout = errors.New("timeout")

	// ErrRateLimit indicates rate limit exceeded (429, RESOURCE_EXHAUSTED)
	ErrRateLimit = errors.New("rate limit exceeded")

	// ErrExternal indicates an external service failure (502, UNAVAILABLE)
	ErrExternal = errors.New("external service error")

	// ErrInvalidConfiguration indicates configuration error
	ErrInvalidConfiguration = errors.New("invalid configuration")
)

// Domain-specific sentinel errors
var (
	// API Key errors
	ErrInvalidAPIKey              = fmt.Errorf("%w: %s", ErrInvalidInput, ERROR_INVALID_API_KEY)
	ErrAPIKeyRequired             = fmt.Errorf("%w: %s", ErrInvalidInput, ERROR_API_KEY_REQUIRED)
	ErrAPIKeyNotFound             = fmt.Errorf("%w: %s", ErrNotFound, ERROR_API_KEY_NOT_FOUND)
	ErrFailedToRetrieveAPIKeyInfo = fmt.Errorf("%w: %s", ErrInternal, ERROR_FAILED_TO_RETRIEVE_API_KEY_INFO)
	ErrFailedToCreateAPIKey       = fmt.Errorf("%w: %s", ErrInternal, ERROR_FAILED_TO_CREATE_API_KEY)
	ErrFailedToUpdateAPIKey       = fmt.Errorf("%w: %s", ErrInternal, ERROR_FAILED_TO_UPDATE_API_KEY)
	ErrFailedToDeleteAPIKey       = fmt.Errorf("%w: %s", ErrInternal, ERROR_FAILED_TO_DELETE_API_KEY)

	// Rate limiting errors
	ErrRateLimitExceeded      = fmt.Errorf("%w: %s", ErrRateLimit, ERROR_RATE_LIMIT_EXCEEDED)
	ErrFailedToCheckRateLimit = fmt.Errorf("%w: %s", ErrInternal, ERROR_FAILED_TO_CHECK_RATE_LIMIT)

	// Authorization errors
	ErrUnauthorizedAccess = fmt.Errorf("%w: %s", ErrUnauthorized, ERROR_UNAUTHORIZED_ACCESS)
	ErrForbiddenOperation = fmt.Errorf("%w: %s", ErrForbidden, ERROR_FORBIDDEN_OPERATION)

	// Configuration errors
	ErrRepositoryRequired = fmt.Errorf("%w: %s", ErrInvalidConfiguration, ERROR_REPOSITORY_REQUIRED)
	ErrFrameworkRequired  = fmt.Errorf("%w: %s", ErrInvalidConfiguration, ERROR_FRAMEWORK_REQUIRED)

	// Validation errors
	ErrMissingUserID = fmt.Errorf("%w: %s", ErrInvalidInput, ERROR_MISSING_USER_ID)
	ErrMissingOrgID  = fmt.Errorf("%w: %s", ErrInvalidInput, ERROR_MISSING_ORG_ID)

	// Bootstrap errors
	ErrBootstrapAlreadyExists = fmt.Errorf("%w: %s", ErrAlreadyExists, ERROR_BOOTSTRAP_ALREADY_EXISTS)
	ErrBootstrapNotEnabled    = fmt.Errorf("%w: %s", ErrInvalidConfiguration, ERROR_BOOTSTRAP_NOT_ENABLED)
)

// Error checking helpers (compatible with errors.Is)
func IsNotFoundError(err error) bool {
	return errors.Is(err, ErrNotFound)
}

func IsAlreadyExistsError(err error) bool {
	return errors.Is(err, ErrAlreadyExists)
}

func IsInvalidInputError(err error) bool {
	return errors.Is(err, ErrInvalidInput)
}

func IsUnauthorizedError(err error) bool {
	return errors.Is(err, ErrUnauthorized)
}

func IsForbiddenError(err error) bool {
	return errors.Is(err, ErrForbidden)
}

func IsInternalError(err error) bool {
	return errors.Is(err, ErrInternal)
}

func IsTimeoutError(err error) bool {
	return errors.Is(err, ErrTimeout)
}

func IsRateLimitError(err error) bool {
	return errors.Is(err, ErrRateLimit)
}

func IsExternalError(err error) bool {
	return errors.Is(err, ErrExternal)
}

func IsConfigurationError(err error) bool {
	return errors.Is(err, ErrInvalidConfiguration)
}

// NewValidationError creates a validation error with field context using go-cuserr
func NewValidationError(field, message string) error {
	return cuserr.NewValidationError(field, message)
}

// NewNotFoundError creates a not found error with resource context using go-cuserr
func NewNotFoundError(resource, identifier string) error {
	return cuserr.NewNotFoundError(resource, identifier)
}

// NewUnauthorizedError creates an unauthorized error with message using go-cuserr
func NewUnauthorizedError(message string) error {
	return cuserr.NewUnauthorizedError(message)
}

// NewForbiddenError creates a forbidden error with operation context using go-cuserr
func NewForbiddenError(operation, resource string) error {
	return cuserr.NewForbiddenError(operation, resource)
}

// NewInternalError creates an internal error with component context using go-cuserr
func NewInternalError(component string, cause error) error {
	return cuserr.NewInternalError(component, cause)
}

// NewTimeoutError creates a timeout error with operation context using go-cuserr
func NewTimeoutError(operation string, cause error) error {
	return cuserr.NewTimeoutError(operation, cause)
}

// NewRateLimitError creates a rate limit error with limit info using go-cuserr
func NewRateLimitError(limit int, window string) error {
	return cuserr.NewRateLimitError(window, window) // cuserr takes limit and window as strings
}

// NewConflictError creates a conflict error with resource context using go-cuserr
func NewConflictError(resource, field, value string) error {
	return cuserr.NewConflictError(resource, field, value)
}

// NewExternalError creates an external service error with context using go-cuserr
func NewExternalError(service, operation string, cause error) error {
	return cuserr.NewExternalError(service, operation, cause)
}

// WrapError wraps an error with additional context using go-cuserr
func WrapError(err error, message string) error {
	if err == nil {
		return nil
	}
	return cuserr.ErrorWithContext(err, message)
}

// WrapErrorf wraps an error with formatted context using go-cuserr
func WrapErrorf(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	message := fmt.Sprintf(format, args...)
	return cuserr.ErrorWithContext(err, message)
}

// ErrorToHTTPStatus maps errors to HTTP status codes
// This is compatible with go-cuserr pattern
func ErrorToHTTPStatus(err error) int {
	if err == nil {
		return 200
	}

	switch {
	case errors.Is(err, ErrNotFound):
		return 404
	case errors.Is(err, ErrAlreadyExists):
		return 409
	case errors.Is(err, ErrInvalidInput):
		return 400
	case errors.Is(err, ErrUnauthorized):
		return 401
	case errors.Is(err, ErrForbidden):
		return 403
	case errors.Is(err, ErrTimeout):
		return 408
	case errors.Is(err, ErrRateLimit):
		return 429
	case errors.Is(err, ErrExternal):
		return 502
	case errors.Is(err, ErrInternal):
		return 500
	default:
		return 500
	}
}

// ErrorToMessage extracts user-safe error message
func ErrorToMessage(err error) string {
	if err == nil {
		return HTTP_MSG_OK
	}

	// Return the error message without internal details
	return err.Error()
}

// ErrorResponse represents a JSON error response
type ErrorResponse struct {
	Error   string                 `json:"error"`
	Message string                 `json:"message"`
	Code    int                    `json:"code"`
	Details map[string]interface{} `json:"details,omitempty"`
}

// NewErrorResponse creates a standardized error response
func NewErrorResponse(err error) *ErrorResponse {
	if err == nil {
		return nil
	}

	return &ErrorResponse{
		Error:   ErrorToMessage(err),
		Message: ErrorToMessage(err),
		Code:    ErrorToHTTPStatus(err),
	}
}

// NewErrorResponseWithDetails creates an error response with additional details
func NewErrorResponseWithDetails(err error, details map[string]interface{}) *ErrorResponse {
	if err == nil {
		return nil
	}

	return &ErrorResponse{
		Error:   ErrorToMessage(err),
		Message: ErrorToMessage(err),
		Code:    ErrorToHTTPStatus(err),
		Details: details,
	}
}
