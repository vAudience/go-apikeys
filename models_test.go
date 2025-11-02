package apikeys

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAPIKeyInfo_Filter(t *testing.T) {
	originalKey := &APIKeyInfo{
		APIKey:     "gak_test123456",
		APIKeyHash: "hash123",
		APIKeyHint: "gak...456",
		UserID:     "user-123",
		OrgID:      "org-456",
		Name:       "Test Key",
		Email:      "test@example.com",
		Roles:      []string{"admin", "user"},
		Rights:     []string{"read", "write"},
		Metadata: map[string]any{
			"key": "value",
		},
	}

	t.Run("include both source and hash", func(t *testing.T) {
		filtered := originalKey.Filter(true, true)
		assert.Equal(t, originalKey.APIKey, filtered.APIKey)
		assert.Equal(t, originalKey.APIKeyHash, filtered.APIKeyHash)
		assert.Equal(t, originalKey.UserID, filtered.UserID)
		assert.Equal(t, originalKey.OrgID, filtered.OrgID)

		// Verify it's a copy, not the original
		assert.NotSame(t, originalKey, filtered)
	})

	t.Run("exclude source, include hash", func(t *testing.T) {
		filtered := originalKey.Filter(false, true)
		assert.Empty(t, filtered.APIKey, "API key should be removed")
		assert.Equal(t, originalKey.APIKeyHash, filtered.APIKeyHash)
		assert.Equal(t, originalKey.UserID, filtered.UserID)
	})

	t.Run("include source, exclude hash", func(t *testing.T) {
		filtered := originalKey.Filter(true, false)
		assert.Equal(t, originalKey.APIKey, filtered.APIKey)
		assert.Empty(t, filtered.APIKeyHash, "Hash should be removed")
		assert.Equal(t, originalKey.UserID, filtered.UserID)
	})

	t.Run("exclude both source and hash", func(t *testing.T) {
		filtered := originalKey.Filter(false, false)
		assert.Empty(t, filtered.APIKey, "API key should be removed")
		assert.Empty(t, filtered.APIKeyHash, "Hash should be removed")
		assert.Equal(t, originalKey.UserID, filtered.UserID)
		assert.Equal(t, originalKey.OrgID, filtered.OrgID)
	})

	t.Run("preserves other fields", func(t *testing.T) {
		filtered := originalKey.Filter(false, false)
		assert.Equal(t, originalKey.UserID, filtered.UserID)
		assert.Equal(t, originalKey.OrgID, filtered.OrgID)
		assert.Equal(t, originalKey.Name, filtered.Name)
		assert.Equal(t, originalKey.Email, filtered.Email)
		assert.Equal(t, originalKey.Roles, filtered.Roles)
		assert.Equal(t, originalKey.Rights, filtered.Rights)
		assert.Equal(t, originalKey.Metadata, filtered.Metadata)
		assert.Equal(t, originalKey.APIKeyHint, filtered.APIKeyHint)
	})

	t.Run("does not mutate original", func(t *testing.T) {
		original := &APIKeyInfo{
			APIKey:     "test-key",
			APIKeyHash: "test-hash",
			UserID:     "user-id",
		}
		originalKeyCopy := original.APIKey
		originalHashCopy := original.APIKeyHash

		filtered := original.Filter(false, false)

		// Original should remain unchanged
		assert.Equal(t, originalKeyCopy, original.APIKey)
		assert.Equal(t, originalHashCopy, original.APIKeyHash)

		// Filtered should be different
		assert.Empty(t, filtered.APIKey)
		assert.Empty(t, filtered.APIKeyHash)
	})
}

func TestAPIKeyInfo_String(t *testing.T) {
	t.Run("returns hash", func(t *testing.T) {
		apiKeyInfo := APIKeyInfo{
			APIKey:     "gak_test123456",
			APIKeyHash: "hash123abc",
			UserID:     "user-123",
		}
		assert.Equal(t, "hash123abc", apiKeyInfo.String())
	})

	t.Run("returns empty for empty hash", func(t *testing.T) {
		apiKeyInfo := APIKeyInfo{
			APIKey: "gak_test123456",
			UserID: "user-123",
		}
		assert.Empty(t, apiKeyInfo.String())
	})

	t.Run("pointer receiver works", func(t *testing.T) {
		apiKeyInfo := &APIKeyInfo{
			APIKeyHash: "hash456def",
			UserID:     "user-456",
		}
		// Should work with pointer as well
		assert.Equal(t, "hash456def", apiKeyInfo.String())
	})
}
