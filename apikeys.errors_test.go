// Package apikeys provides API key authentication and management middleware for Go applications.
//
// This file tests all error handling functions to ensure proper error type detection,
// error construction, and HTTP status code mapping.
package apikeys

import (
	"errors"
	"fmt"
	"testing"

	"github.com/itsatony/go-cuserr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Error Checker Tests (10 tests)
// =============================================================================

func TestIsNotFoundError(t *testing.T) {
	t.Run("detects not found error", func(t *testing.T) {
		err := ErrNotFound
		assert.True(t, IsNotFoundError(err))
	})

	t.Run("detects wrapped not found error", func(t *testing.T) {
		err := fmt.Errorf("wrapped: %w", ErrNotFound)
		assert.True(t, IsNotFoundError(err))
	})

	t.Run("detects domain not found error", func(t *testing.T) {
		assert.True(t, IsNotFoundError(ErrAPIKeyNotFound))
	})

	t.Run("returns false for different error", func(t *testing.T) {
		err := ErrInvalidInput
		assert.False(t, IsNotFoundError(err))
	})

	t.Run("returns false for nil", func(t *testing.T) {
		assert.False(t, IsNotFoundError(nil))
	})
}

func TestIsAlreadyExistsError(t *testing.T) {
	t.Run("detects already exists error", func(t *testing.T) {
		err := ErrAlreadyExists
		assert.True(t, IsAlreadyExistsError(err))
	})

	t.Run("detects wrapped already exists error", func(t *testing.T) {
		err := fmt.Errorf("wrapped: %w", ErrAlreadyExists)
		assert.True(t, IsAlreadyExistsError(err))
	})

	t.Run("detects bootstrap already exists error", func(t *testing.T) {
		assert.True(t, IsAlreadyExistsError(ErrBootstrapAlreadyExists))
	})

	t.Run("returns false for different error", func(t *testing.T) {
		assert.False(t, IsAlreadyExistsError(ErrNotFound))
	})

	t.Run("returns false for nil", func(t *testing.T) {
		assert.False(t, IsAlreadyExistsError(nil))
	})
}

func TestIsInvalidInputError(t *testing.T) {
	t.Run("detects invalid input error", func(t *testing.T) {
		err := ErrInvalidInput
		assert.True(t, IsInvalidInputError(err))
	})

	t.Run("detects wrapped invalid input error", func(t *testing.T) {
		err := fmt.Errorf("wrapped: %w", ErrInvalidInput)
		assert.True(t, IsInvalidInputError(err))
	})

	t.Run("detects domain invalid input errors", func(t *testing.T) {
		assert.True(t, IsInvalidInputError(ErrInvalidAPIKey))
		assert.True(t, IsInvalidInputError(ErrAPIKeyRequired))
		assert.True(t, IsInvalidInputError(ErrMissingUserID))
		assert.True(t, IsInvalidInputError(ErrMissingOrgID))
	})

	t.Run("returns false for different error", func(t *testing.T) {
		assert.False(t, IsInvalidInputError(ErrUnauthorized))
	})

	t.Run("returns false for nil", func(t *testing.T) {
		assert.False(t, IsInvalidInputError(nil))
	})
}

func TestIsUnauthorizedError(t *testing.T) {
	t.Run("detects unauthorized error", func(t *testing.T) {
		err := ErrUnauthorized
		assert.True(t, IsUnauthorizedError(err))
	})

	t.Run("detects wrapped unauthorized error", func(t *testing.T) {
		err := fmt.Errorf("wrapped: %w", ErrUnauthorized)
		assert.True(t, IsUnauthorizedError(err))
	})

	t.Run("detects unauthorized access error", func(t *testing.T) {
		assert.True(t, IsUnauthorizedError(ErrUnauthorizedAccess))
	})

	t.Run("returns false for different error", func(t *testing.T) {
		assert.False(t, IsUnauthorizedError(ErrForbidden))
	})

	t.Run("returns false for nil", func(t *testing.T) {
		assert.False(t, IsUnauthorizedError(nil))
	})
}

func TestIsForbiddenError(t *testing.T) {
	t.Run("detects forbidden error", func(t *testing.T) {
		err := ErrForbidden
		assert.True(t, IsForbiddenError(err))
	})

	t.Run("detects wrapped forbidden error", func(t *testing.T) {
		err := fmt.Errorf("wrapped: %w", ErrForbidden)
		assert.True(t, IsForbiddenError(err))
	})

	t.Run("detects forbidden operation error", func(t *testing.T) {
		assert.True(t, IsForbiddenError(ErrForbiddenOperation))
	})

	t.Run("returns false for different error", func(t *testing.T) {
		assert.False(t, IsForbiddenError(ErrUnauthorized))
	})

	t.Run("returns false for nil", func(t *testing.T) {
		assert.False(t, IsForbiddenError(nil))
	})
}

func TestIsInternalError(t *testing.T) {
	t.Run("detects internal error", func(t *testing.T) {
		err := ErrInternal
		assert.True(t, IsInternalError(err))
	})

	t.Run("detects wrapped internal error", func(t *testing.T) {
		err := fmt.Errorf("wrapped: %w", ErrInternal)
		assert.True(t, IsInternalError(err))
	})

	t.Run("detects domain internal errors", func(t *testing.T) {
		assert.True(t, IsInternalError(ErrFailedToRetrieveAPIKeyInfo))
		assert.True(t, IsInternalError(ErrFailedToCreateAPIKey))
		assert.True(t, IsInternalError(ErrFailedToUpdateAPIKey))
		assert.True(t, IsInternalError(ErrFailedToDeleteAPIKey))
		assert.True(t, IsInternalError(ErrFailedToCheckRateLimit))
	})

	t.Run("returns false for different error", func(t *testing.T) {
		assert.False(t, IsInternalError(ErrNotFound))
	})

	t.Run("returns false for nil", func(t *testing.T) {
		assert.False(t, IsInternalError(nil))
	})
}

func TestIsTimeoutError(t *testing.T) {
	t.Run("detects timeout error", func(t *testing.T) {
		err := ErrTimeout
		assert.True(t, IsTimeoutError(err))
	})

	t.Run("detects wrapped timeout error", func(t *testing.T) {
		err := fmt.Errorf("wrapped: %w", ErrTimeout)
		assert.True(t, IsTimeoutError(err))
	})

	t.Run("returns false for different error", func(t *testing.T) {
		assert.False(t, IsTimeoutError(ErrRateLimit))
	})

	t.Run("returns false for nil", func(t *testing.T) {
		assert.False(t, IsTimeoutError(nil))
	})
}

func TestIsRateLimitError(t *testing.T) {
	t.Run("detects rate limit error", func(t *testing.T) {
		err := ErrRateLimit
		assert.True(t, IsRateLimitError(err))
	})

	t.Run("detects wrapped rate limit error", func(t *testing.T) {
		err := fmt.Errorf("wrapped: %w", ErrRateLimit)
		assert.True(t, IsRateLimitError(err))
	})

	t.Run("detects rate limit exceeded error", func(t *testing.T) {
		assert.True(t, IsRateLimitError(ErrRateLimitExceeded))
	})

	t.Run("returns false for different error", func(t *testing.T) {
		assert.False(t, IsRateLimitError(ErrTimeout))
	})

	t.Run("returns false for nil", func(t *testing.T) {
		assert.False(t, IsRateLimitError(nil))
	})
}

func TestIsExternalError(t *testing.T) {
	t.Run("detects external error", func(t *testing.T) {
		err := ErrExternal
		assert.True(t, IsExternalError(err))
	})

	t.Run("detects wrapped external error", func(t *testing.T) {
		err := fmt.Errorf("wrapped: %w", ErrExternal)
		assert.True(t, IsExternalError(err))
	})

	t.Run("returns false for different error", func(t *testing.T) {
		assert.False(t, IsExternalError(ErrInternal))
	})

	t.Run("returns false for nil", func(t *testing.T) {
		assert.False(t, IsExternalError(nil))
	})
}

func TestIsConfigurationError(t *testing.T) {
	t.Run("detects configuration error", func(t *testing.T) {
		err := ErrInvalidConfiguration
		assert.True(t, IsConfigurationError(err))
	})

	t.Run("detects wrapped configuration error", func(t *testing.T) {
		err := fmt.Errorf("wrapped: %w", ErrInvalidConfiguration)
		assert.True(t, IsConfigurationError(err))
	})

	t.Run("detects domain configuration errors", func(t *testing.T) {
		assert.True(t, IsConfigurationError(ErrRepositoryRequired))
		assert.True(t, IsConfigurationError(ErrFrameworkRequired))
		assert.True(t, IsConfigurationError(ErrBootstrapNotEnabled))
	})

	t.Run("returns false for different error", func(t *testing.T) {
		assert.False(t, IsConfigurationError(ErrInvalidInput))
	})

	t.Run("returns false for nil", func(t *testing.T) {
		assert.False(t, IsConfigurationError(nil))
	})
}

// =============================================================================
// Error Constructor Tests (8 tests)
// =============================================================================

func TestNewValidationError(t *testing.T) {
	t.Run("creates validation error with field and message", func(t *testing.T) {
		err := NewValidationError("email", "invalid format")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid format")
		// Field is stored in cuserr metadata, check it there
		if cerr, ok := err.(*cuserr.CustomError); ok {
			field, exists := cerr.GetMetadata("field")
			assert.True(t, exists, "field metadata should exist")
			assert.Equal(t, "email", field)
		} else {
			t.Fatal("expected *cuserr.CustomError")
		}
	})

	t.Run("maps to correct HTTP status", func(t *testing.T) {
		err := NewValidationError("field", "message")
		// go-cuserr validation errors should map to 400
		status := ErrorToHTTPStatus(err)
		assert.Equal(t, 400, status)
	})
}

func TestNewNotFoundError(t *testing.T) {
	t.Run("creates not found error with resource and identifier", func(t *testing.T) {
		err := NewNotFoundError("api_key", "abc123")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api_key")
		assert.Contains(t, err.Error(), "abc123")
	})

	t.Run("maps to correct HTTP status", func(t *testing.T) {
		err := NewNotFoundError("resource", "id")
		status := ErrorToHTTPStatus(err)
		assert.Equal(t, 404, status)
	})
}

func TestNewUnauthorizedError(t *testing.T) {
	t.Run("creates unauthorized error with message", func(t *testing.T) {
		err := NewUnauthorizedError("invalid API key")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid API key")
	})

	t.Run("maps to correct HTTP status", func(t *testing.T) {
		err := NewUnauthorizedError("test message")
		status := ErrorToHTTPStatus(err)
		assert.Equal(t, 401, status)
	})
}

func TestNewForbiddenError(t *testing.T) {
	t.Run("creates forbidden error with operation and resource", func(t *testing.T) {
		err := NewForbiddenError("delete", "api_key")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "delete")
		assert.Contains(t, err.Error(), "api_key")
	})

	t.Run("maps to correct HTTP status", func(t *testing.T) {
		err := NewForbiddenError("operation", "resource")
		status := ErrorToHTTPStatus(err)
		assert.Equal(t, 403, status)
	})
}

func TestNewInternalError(t *testing.T) {
	t.Run("creates internal error with component and cause", func(t *testing.T) {
		cause := errors.New("database connection failed")
		err := NewInternalError("repository", cause)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "repository")
	})

	t.Run("maps to correct HTTP status", func(t *testing.T) {
		err := NewInternalError("component", errors.New("cause"))
		status := ErrorToHTTPStatus(err)
		assert.Equal(t, 500, status)
	})

	t.Run("wraps cause error", func(t *testing.T) {
		cause := errors.New("original error")
		err := NewInternalError("test", cause)
		// go-cuserr wraps the cause
		assert.ErrorIs(t, err, cause)
	})
}

func TestNewTimeoutError(t *testing.T) {
	t.Run("creates timeout error with operation and cause", func(t *testing.T) {
		cause := errors.New("context deadline exceeded")
		err := NewTimeoutError("database_query", cause)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "database_query")
	})

	t.Run("maps to correct HTTP status", func(t *testing.T) {
		err := NewTimeoutError("operation", errors.New("timeout"))
		status := ErrorToHTTPStatus(err)
		assert.Equal(t, 408, status)
	})
}

func TestNewRateLimitError(t *testing.T) {
	t.Run("creates rate limit error with limit and window", func(t *testing.T) {
		err := NewRateLimitError(100, "60s")
		require.Error(t, err)
		// Should contain window information
		assert.NotEmpty(t, err.Error())
	})

	t.Run("maps to correct HTTP status", func(t *testing.T) {
		err := NewRateLimitError(50, "1m")
		status := ErrorToHTTPStatus(err)
		assert.Equal(t, 429, status)
	})
}

func TestNewConflictError(t *testing.T) {
	t.Run("creates conflict error with resource, field, and value", func(t *testing.T) {
		err := NewConflictError("api_key", "hash", "abc123")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "api_key")
		assert.Contains(t, err.Error(), "hash")
	})

	t.Run("maps to correct HTTP status", func(t *testing.T) {
		err := NewConflictError("resource", "field", "value")
		status := ErrorToHTTPStatus(err)
		assert.Equal(t, 409, status)
	})
}

func TestNewExternalError(t *testing.T) {
	t.Run("creates external error with service, operation, and cause", func(t *testing.T) {
		cause := errors.New("connection refused")
		err := NewExternalError("redis", "get", cause)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "redis")
		// Operation is stored in cuserr metadata, check it there
		if cerr, ok := err.(*cuserr.CustomError); ok {
			operation, exists := cerr.GetMetadata("operation")
			assert.True(t, exists, "operation metadata should exist")
			assert.Equal(t, "get", operation)
		} else {
			t.Fatal("expected *cuserr.CustomError")
		}
	})

	t.Run("maps to correct HTTP status", func(t *testing.T) {
		err := NewExternalError("service", "op", errors.New("cause"))
		status := ErrorToHTTPStatus(err)
		assert.Equal(t, 502, status)
	})
}

// =============================================================================
// Error Wrapping Tests (2 tests)
// =============================================================================

func TestWrapError(t *testing.T) {
	t.Run("wraps error with context", func(t *testing.T) {
		original := errors.New("original error")
		wrapped := WrapError(original, "additional context")
		require.Error(t, wrapped)
		assert.Contains(t, wrapped.Error(), "additional context")
		assert.ErrorIs(t, wrapped, original)
	})

	t.Run("returns nil for nil error", func(t *testing.T) {
		wrapped := WrapError(nil, "context")
		assert.Nil(t, wrapped)
	})

	t.Run("preserves error type", func(t *testing.T) {
		original := ErrNotFound
		wrapped := WrapError(original, "context")
		assert.True(t, IsNotFoundError(wrapped))
	})
}

func TestWrapErrorf(t *testing.T) {
	t.Run("wraps error with formatted context", func(t *testing.T) {
		original := errors.New("original error")
		wrapped := WrapErrorf(original, "failed to process %s: %d", "user", 123)
		require.Error(t, wrapped)
		assert.Contains(t, wrapped.Error(), "failed to process user: 123")
		assert.ErrorIs(t, wrapped, original)
	})

	t.Run("returns nil for nil error", func(t *testing.T) {
		wrapped := WrapErrorf(nil, "format %s", "arg")
		assert.Nil(t, wrapped)
	})

	t.Run("preserves error type", func(t *testing.T) {
		original := ErrUnauthorized
		wrapped := WrapErrorf(original, "user %s failed", "bob")
		assert.True(t, IsUnauthorizedError(wrapped))
	})
}

// =============================================================================
// HTTP Status Code Mapping Tests (1 test with multiple cases)
// =============================================================================

func TestErrorToHTTPStatus(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		status int
	}{
		{"nil error returns 200", nil, 200},
		{"not found returns 404", ErrNotFound, 404},
		{"already exists returns 409", ErrAlreadyExists, 409},
		{"invalid input returns 400", ErrInvalidInput, 400},
		{"unauthorized returns 401", ErrUnauthorized, 401},
		{"forbidden returns 403", ErrForbidden, 403},
		{"timeout returns 408", ErrTimeout, 408},
		{"rate limit returns 429", ErrRateLimit, 429},
		{"external returns 502", ErrExternal, 502},
		{"internal returns 500", ErrInternal, 500},
		{"unknown returns 500", errors.New("unknown"), 500},
		{"wrapped not found returns 404", fmt.Errorf("wrapped: %w", ErrNotFound), 404},
		{"domain api key not found returns 404", ErrAPIKeyNotFound, 404},
		{"domain invalid api key returns 400", ErrInvalidAPIKey, 400},
		{"domain unauthorized access returns 401", ErrUnauthorizedAccess, 401},
		{"domain rate limit exceeded returns 429", ErrRateLimitExceeded, 429},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status := ErrorToHTTPStatus(tt.err)
			assert.Equal(t, tt.status, status)
		})
	}
}

// =============================================================================
// Error Message Extraction Tests (1 test)
// =============================================================================

func TestErrorToMessage(t *testing.T) {
	t.Run("returns OK for nil", func(t *testing.T) {
		msg := ErrorToMessage(nil)
		assert.Equal(t, HTTP_MSG_OK, msg)
	})

	t.Run("returns error message", func(t *testing.T) {
		err := errors.New("test error message")
		msg := ErrorToMessage(err)
		assert.Equal(t, "test error message", msg)
	})

	t.Run("returns message for wrapped error", func(t *testing.T) {
		original := errors.New("original")
		wrapped := fmt.Errorf("wrapped: %w", original)
		msg := ErrorToMessage(wrapped)
		assert.Contains(t, msg, "wrapped")
		assert.Contains(t, msg, "original")
	})
}

// =============================================================================
// Error Response Tests (2 tests)
// =============================================================================

func TestNewErrorResponse(t *testing.T) {
	t.Run("returns nil for nil error", func(t *testing.T) {
		resp := NewErrorResponse(nil)
		assert.Nil(t, resp)
	})

	t.Run("creates error response with correct fields", func(t *testing.T) {
		err := ErrNotFound
		resp := NewErrorResponse(err)
		require.NotNil(t, resp)
		assert.NotEmpty(t, resp.Error)
		assert.NotEmpty(t, resp.Message)
		assert.Equal(t, 404, resp.Code)
		assert.Nil(t, resp.Details)
	})

	t.Run("maps domain errors correctly", func(t *testing.T) {
		err := ErrAPIKeyNotFound
		resp := NewErrorResponse(err)
		require.NotNil(t, resp)
		assert.Equal(t, 404, resp.Code)
	})
}

func TestNewErrorResponseWithDetails(t *testing.T) {
	t.Run("returns nil for nil error", func(t *testing.T) {
		details := map[string]interface{}{"key": "value"}
		resp := NewErrorResponseWithDetails(nil, details)
		assert.Nil(t, resp)
	})

	t.Run("creates error response with details", func(t *testing.T) {
		err := ErrInvalidInput
		details := map[string]interface{}{
			"field":  "email",
			"reason": "invalid format",
		}
		resp := NewErrorResponseWithDetails(err, details)
		require.NotNil(t, resp)
		assert.NotEmpty(t, resp.Error)
		assert.Equal(t, 400, resp.Code)
		assert.NotNil(t, resp.Details)
		assert.Equal(t, "email", resp.Details["field"])
		assert.Equal(t, "invalid format", resp.Details["reason"])
	})

	t.Run("handles nil details gracefully", func(t *testing.T) {
		err := ErrUnauthorized
		resp := NewErrorResponseWithDetails(err, nil)
		require.NotNil(t, resp)
		assert.Equal(t, 401, resp.Code)
		// Details can be nil
	})
}

// =============================================================================
// Edge Case Tests (3 tests)
// =============================================================================

func TestErrorCheckersWithNilError(t *testing.T) {
	t.Run("all checkers return false for nil", func(t *testing.T) {
		assert.False(t, IsNotFoundError(nil))
		assert.False(t, IsAlreadyExistsError(nil))
		assert.False(t, IsInvalidInputError(nil))
		assert.False(t, IsUnauthorizedError(nil))
		assert.False(t, IsForbiddenError(nil))
		assert.False(t, IsInternalError(nil))
		assert.False(t, IsTimeoutError(nil))
		assert.False(t, IsRateLimitError(nil))
		assert.False(t, IsExternalError(nil))
		assert.False(t, IsConfigurationError(nil))
	})
}

func TestErrorCheckersWithCustomError(t *testing.T) {
	t.Run("checkers return false for unrelated custom error", func(t *testing.T) {
		customErr := errors.New("custom error type")

		assert.False(t, IsNotFoundError(customErr))
		assert.False(t, IsAlreadyExistsError(customErr))
		assert.False(t, IsInvalidInputError(customErr))
		assert.False(t, IsUnauthorizedError(customErr))
		assert.False(t, IsForbiddenError(customErr))
		assert.False(t, IsInternalError(customErr))
		assert.False(t, IsTimeoutError(customErr))
		assert.False(t, IsRateLimitError(customErr))
		assert.False(t, IsExternalError(customErr))
		assert.False(t, IsConfigurationError(customErr))
	})
}

func TestErrorChainWalking(t *testing.T) {
	t.Run("error checkers walk error chain", func(t *testing.T) {
		// Create a chain: custom -> wrapped -> base
		base := ErrNotFound
		wrapped := WrapError(base, "additional context")
		doubleWrapped := fmt.Errorf("outer: %w", wrapped)

		// Should still detect the base error type
		assert.True(t, IsNotFoundError(doubleWrapped))
	})

	t.Run("http status walks error chain", func(t *testing.T) {
		base := ErrRateLimit
		wrapped := WrapErrorf(base, "rate limit for user %s", "bob")
		doubleWrapped := fmt.Errorf("operation failed: %w", wrapped)

		status := ErrorToHTTPStatus(doubleWrapped)
		assert.Equal(t, 429, status)
	})

	t.Run("multiple wrapping preserves type for sentinel errors", func(t *testing.T) {
		// Use sentinel error instead of NewValidationError since go-cuserr
		// validation errors may not preserve through multiple wrappings
		base := ErrInvalidInput
		wrapped1 := WrapError(base, "context 1")
		wrapped2 := WrapError(wrapped1, "context 2")
		wrapped3 := WrapErrorf(wrapped2, "context %d", 3)

		assert.True(t, IsInvalidInputError(wrapped3))
		assert.Equal(t, 400, ErrorToHTTPStatus(wrapped3))
	})
}
