package apikeys

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateAPIKeyInfo(t *testing.T) {
	t.Run("valid API key info", func(t *testing.T) {
		info := &APIKeyInfo{
			UserID: "user-123",
			OrgID:  "org-456",
			Email:  "user@example.com",
			Name:   "Test Key",
		}
		err := ValidateAPIKeyInfo(info)
		assert.NoError(t, err)
	})

	t.Run("missing user_id", func(t *testing.T) {
		info := &APIKeyInfo{
			OrgID: "org-456",
		}
		err := ValidateAPIKeyInfo(info)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user_id")
	})

	t.Run("missing org_id", func(t *testing.T) {
		info := &APIKeyInfo{
			UserID: "user-123",
		}
		err := ValidateAPIKeyInfo(info)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "org_id")
	})

	t.Run("user_id too long", func(t *testing.T) {
		info := &APIKeyInfo{
			UserID: strings.Repeat("a", MAX_USER_ID_LENGTH+1),
			OrgID:  "org-456",
		}
		err := ValidateAPIKeyInfo(info)
		assert.Error(t, err)
	})

	t.Run("org_id too long", func(t *testing.T) {
		info := &APIKeyInfo{
			UserID: "user-123",
			OrgID:  strings.Repeat("a", MAX_ORG_ID_LENGTH+1),
		}
		err := ValidateAPIKeyInfo(info)
		assert.Error(t, err)
	})

	t.Run("invalid email format", func(t *testing.T) {
		info := &APIKeyInfo{
			UserID: "user-123",
			OrgID:  "org-456",
			Email:  "invalid-email",
		}
		err := ValidateAPIKeyInfo(info)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "email")
	})

	t.Run("valid without email", func(t *testing.T) {
		info := &APIKeyInfo{
			UserID: "user-123",
			OrgID:  "org-456",
		}
		err := ValidateAPIKeyInfo(info)
		assert.NoError(t, err)
	})

	t.Run("empty email is valid", func(t *testing.T) {
		info := &APIKeyInfo{
			UserID: "user-123",
			OrgID:  "org-456",
			Email:  "",
		}
		err := ValidateAPIKeyInfo(info)
		assert.NoError(t, err)
	})

	t.Run("nil info", func(t *testing.T) {
		err := ValidateAPIKeyInfo(nil)
		assert.Error(t, err)
	})
}

func TestValidateAPIKey(t *testing.T) {
	t.Run("valid API key", func(t *testing.T) {
		key, _ := GenerateAPIKey(DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH)
		err := ValidateAPIKey(key)
		assert.NoError(t, err)
	})

	t.Run("empty key", func(t *testing.T) {
		err := ValidateAPIKey("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "required")
	})

	t.Run("invalid key format", func(t *testing.T) {
		err := ValidateAPIKey("invalid-key")
		assert.Error(t, err)
	})

	t.Run("key too short", func(t *testing.T) {
		err := ValidateAPIKey("gak_short")
		assert.Error(t, err)
	})
}

func TestSanitizeAPIKeyInfo(t *testing.T) {
	t.Run("trims whitespace", func(t *testing.T) {
		info := &APIKeyInfo{
			UserID: "  user-123  ",
			OrgID:  "  org-456  ",
			Name:   "  Test Key  ",
			Email:  "  user@example.com  ",
		}
		SanitizeAPIKeyInfo(info)
		assert.Equal(t, "user-123", info.UserID)
		assert.Equal(t, "org-456", info.OrgID)
		assert.Equal(t, "Test Key", info.Name)
		assert.Equal(t, "user@example.com", info.Email)
	})

	t.Run("does not lowercase email", func(t *testing.T) {
		info := &APIKeyInfo{
			UserID: "user-123",
			OrgID:  "org-456",
			Email:  "User@EXAMPLE.COM",
		}
		SanitizeAPIKeyInfo(info)
		// SanitizeString only trims, doesn't lowercase
		assert.Equal(t, "User@EXAMPLE.COM", info.Email)
	})

	t.Run("handles nil", func(t *testing.T) {
		// Should not panic
		assert.NotPanics(t, func() {
			SanitizeAPIKeyInfo(nil)
		})
	})

	t.Run("handles empty strings", func(t *testing.T) {
		info := &APIKeyInfo{
			UserID: "",
			OrgID:  "",
			Email:  "",
		}
		assert.NotPanics(t, func() {
			SanitizeAPIKeyInfo(info)
		})
	})
}

func TestValidateEmail(t *testing.T) {
	validEmails := []string{
		"user@example.com",
		"test.user@example.com",
		"user+tag@example.co.uk",
	}

	for _, email := range validEmails {
		t.Run("valid: "+email, func(t *testing.T) {
			err := ValidateEmail(email)
			assert.NoError(t, err)
		})
	}

	t.Run("empty email is valid (optional field)", func(t *testing.T) {
		err := ValidateEmail("")
		assert.NoError(t, err, "Empty email should be valid as it's optional")
	})

	invalidEmails := []string{
		"invalid",
		"@example.com",
		"user@",
		"user@@example.com",
		"user @example.com",
		"ab", // too short
	}

	for _, email := range invalidEmails {
		t.Run("invalid: "+email, func(t *testing.T) {
			err := ValidateEmail(email)
			assert.Error(t, err)
		})
	}
}
