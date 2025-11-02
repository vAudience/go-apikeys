package apikeys

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAPIKey(t *testing.T) {
	t.Run("successful generation with default length", func(t *testing.T) {
		key, err := GenerateAPIKey(DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(key, DEFAULT_APIKEY_PREFIX))
		assert.Len(t, key, len(DEFAULT_APIKEY_PREFIX)+DEFAULT_APIKEY_LENGTH)
	})

	t.Run("successful generation with custom length", func(t *testing.T) {
		key, err := GenerateAPIKey("custom_", 16)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(key, "custom_"))
		assert.Len(t, key, len("custom_")+16)
	})

	t.Run("generates unique keys", func(t *testing.T) {
		key1, err1 := GenerateAPIKey(DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH)
		key2, err2 := GenerateAPIKey(DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH)
		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.NotEqual(t, key1, key2, "Generated keys should be unique")
	})

	t.Run("empty prefix returns error", func(t *testing.T) {
		_, err := GenerateAPIKey("", DEFAULT_APIKEY_LENGTH)
		assert.Error(t, err)
		// cuserr validation errors contain field name and message
		errMsg := err.Error()
		assert.True(t, strings.Contains(errMsg, "prefix") || strings.Contains(errMsg, "cannot be empty"),
			"error should mention field or validation failure")
	})
}

func TestGenerateAPIKeyHash(t *testing.T) {
	t.Run("successful hash generation", func(t *testing.T) {
		apiKey := "gak_test123456789"
		hash, hint, err := GenerateAPIKeyHash(apiKey)
		require.NoError(t, err)
		assert.NotEmpty(t, hash)
		assert.NotEmpty(t, hint)
		assert.Len(t, hash, 128) // SHA3-512 = 64 bytes = 128 hex chars
	})

	t.Run("hint format", func(t *testing.T) {
		apiKey := "gak_test123456789"
		_, hint, err := GenerateAPIKeyHash(apiKey)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(hint, "gak"))
		assert.True(t, strings.HasSuffix(hint, "789"))
		assert.Contains(t, hint, "...")
	})

	t.Run("same key generates same hash", func(t *testing.T) {
		apiKey := "gak_test123456789"
		hash1, _, err1 := GenerateAPIKeyHash(apiKey)
		hash2, _, err2 := GenerateAPIKeyHash(apiKey)
		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.Equal(t, hash1, hash2, "Same key should generate same hash")
	})

	t.Run("different keys generate different hashes", func(t *testing.T) {
		hash1, _, err1 := GenerateAPIKeyHash("gak_key1")
		hash2, _, err2 := GenerateAPIKeyHash("gak_key2")
		require.NoError(t, err1)
		require.NoError(t, err2)
		assert.NotEqual(t, hash1, hash2, "Different keys should generate different hashes")
	})

	t.Run("empty key returns error", func(t *testing.T) {
		_, _, err := GenerateAPIKeyHash("")
		assert.Error(t, err)
		// cuserr validation errors contain field name and message
		errMsg := err.Error()
		assert.True(t, strings.Contains(errMsg, "api_key") || strings.Contains(errMsg, "cannot be empty"),
			"error should mention field or validation failure")
	})
}

func TestIsAPIKey(t *testing.T) {
	t.Run("valid API key with default prefix", func(t *testing.T) {
		key, _ := GenerateAPIKey(DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH)
		assert.True(t, IsAPIKey(key))
	})

	t.Run("valid API key minimum length", func(t *testing.T) {
		key, _ := GenerateAPIKey(DEFAULT_APIKEY_PREFIX, 10)
		assert.True(t, IsAPIKey(key))
	})

	t.Run("invalid - too short", func(t *testing.T) {
		assert.False(t, IsAPIKey("gak_short"))
	})

	t.Run("valid - lowercase prefix (2-5 chars)", func(t *testing.T) {
		key, _ := GenerateAPIKey("abc_", DEFAULT_APIKEY_LENGTH)
		assert.True(t, IsAPIKey(key), "Prefix with 2-5 lowercase letters should be valid")
	})

	t.Run("invalid - prefix too long", func(t *testing.T) {
		key, _ := GenerateAPIKey("toolong_", DEFAULT_APIKEY_LENGTH)
		assert.False(t, IsAPIKey(key), "Prefix longer than 5 chars should be invalid")
	})

	t.Run("invalid - no underscore separator", func(t *testing.T) {
		assert.False(t, IsAPIKey("nounderscorehere123456789"))
	})

	t.Run("invalid - empty string", func(t *testing.T) {
		assert.False(t, IsAPIKey(""))
	})

	t.Run("invalid - hash format", func(t *testing.T) {
		// SHA3-512 hash (128 hex chars) should not be identified as API key
		hash := strings.Repeat("a", 128)
		assert.False(t, IsAPIKey(hash))
	})
}

func TestCompareAPIKeyHash(t *testing.T) {
	apiKey := "gak_test123456789"
	hash, _, _ := GenerateAPIKeyHash(apiKey)

	t.Run("correct key matches hash", func(t *testing.T) {
		match := CompareAPIKeyHash(apiKey, hash)
		assert.True(t, match)
	})

	t.Run("incorrect key does not match", func(t *testing.T) {
		wrongKey := "gak_wrong123456789"
		match := CompareAPIKeyHash(wrongKey, hash)
		assert.False(t, match)
	})

	t.Run("empty key does not match", func(t *testing.T) {
		match := CompareAPIKeyHash("", hash)
		assert.False(t, match)
	})

	t.Run("empty hash does not match", func(t *testing.T) {
		match := CompareAPIKeyHash(apiKey, "")
		assert.False(t, match)
	})
}
