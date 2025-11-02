// Package apikeys provides API key authentication and management middleware for Go applications.
//
// This file contains utility/helper functions for API key generation, hashing, and validation.
package apikeys

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"

	gonanoid "github.com/matoous/go-nanoid/v2"
)

// GenerateAPIKey generates a new API key with the specified prefix and length.
// Returns (apiKey, error) - never panics.
//
// The generated key format is: {prefix}{random_string}
// Example: "gak_6ByTSYmGzT2czT2c9Xd2kPqRs8Vx"
//
// This function is thread-safe and can be called concurrently.
func GenerateAPIKey(prefix string, length int) (string, error) {
	if prefix == "" {
		return "", NewValidationError("prefix", "cannot be empty")
	}
	if length < 10 {
		return "", NewValidationError("length", fmt.Sprintf("must be at least 10 (got %d)", length))
	}

	// Generate random string using go-nanoid
	randomString, err := gonanoid.New(length)
	if err != nil {
		return "", NewInternalError("nanoid_generation", err)
	}

	apiKey := prefix + randomString
	return apiKey, nil
}

// GenerateAPIKeyHash generates a SHA3-512 hash of the API key.
// Returns (hash, hint, error).
//
// The hash is used for secure storage and comparison.
// The hint shows first 3 and last 3 characters for user reference.
//
// Example:
//
//	hash: "a1b2c3d4..."
//	hint: "gak...8Vx"
//
// This function is thread-safe and can be called concurrently.
func GenerateAPIKeyHash(apiKey string) (hash string, hint string, err error) {
	if apiKey == "" {
		return "", "", NewValidationError("api_key", "cannot be empty")
	}

	// Generate SHA3-512 hash
	hasher := sha512.New()
	_, err = hasher.Write([]byte(apiKey))
	if err != nil {
		return "", "", NewInternalError("hash_generation", err)
	}

	hashBytes := hasher.Sum(nil)
	hash = hex.EncodeToString(hashBytes)

	// Generate hint (first 3 + "..." + last 3 characters)
	hint = generateAPIKeyHint(apiKey)

	return hash, hint, nil
}

// generateAPIKeyHint creates a hint from the API key showing first/last characters.
// Format: "abc...xyz"
func generateAPIKeyHint(apiKey string) string {
	if len(apiKey) <= 6 {
		return apiKey // Too short, just return as-is
	}

	firstPart := apiKey[:DEFAULT_APIKEY_HINT_LENGTH]
	lastPart := apiKey[len(apiKey)-DEFAULT_APIKEY_HINT_LENGTH:]
	return fmt.Sprintf("%s...%s", firstPart, lastPart)
}

// IsAPIKey validates if a string matches the API key format.
// Returns true if the format is valid (prefix + random string).
//
// Valid format: {2-5 lowercase letters}_{10+ alphanumeric/dash/underscore}
// Examples:
//   - "gak_6ByTSYmGzT2c" ✓
//   - "test_abc123"      ✓
//   - "invalid"          ✗
//   - "toolong_"         ✗
func IsAPIKey(apiKey string) bool {
	if apiKey == "" {
		return false
	}

	// Check minimum length
	if len(apiKey) < MIN_APIKEY_LENGTH {
		return false
	}

	// Check format: prefix_randomstring
	parts := strings.SplitN(apiKey, "_", 2)
	if len(parts) != 2 {
		return false // No underscore separator
	}

	prefix := parts[0]
	randomPart := parts[1]

	// Validate prefix (2-5 lowercase letters)
	if len(prefix) < 2 || len(prefix) > 5 {
		return false
	}
	for _, char := range prefix {
		if char < 'a' || char > 'z' {
			return false // Prefix must be lowercase letters only
		}
	}

	// Validate random part (at least 10 characters)
	if len(randomPart) < 10 {
		return false
	}

	// Random part can contain alphanumeric, dash, underscore
	for _, char := range randomPart {
		if !((char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '-' || char == '_') {
			return false
		}
	}

	return true
}

// HashAPIKey is a convenience function that validates and hashes an API key.
// Returns (hash, hint, error).
//
// This combines validation (IsAPIKey) and hashing (GenerateAPIKeyHash).
func HashAPIKey(apiKey string) (hash string, hint string, err error) {
	if !IsAPIKey(apiKey) {
		return "", "", ErrInvalidAPIKey
	}

	return GenerateAPIKeyHash(apiKey)
}

// CompareAPIKeyHash compares a plain API key with a stored hash.
// Returns true if they match, false otherwise.
//
// This is a constant-time comparison to prevent timing attacks.
func CompareAPIKeyHash(apiKey string, storedHash string) bool {
	hash, _, err := GenerateAPIKeyHash(apiKey)
	if err != nil {
		return false
	}

	// Constant-time comparison to prevent timing attacks
	if len(hash) != len(storedHash) {
		return false
	}

	result := 0
	for i := 0; i < len(hash); i++ {
		result |= int(hash[i] ^ storedHash[i])
	}

	return result == 0
}

// emptyLogger is a no-op logger used when no logger is provided.
// This prevents nil pointer dereferences.
func emptyLogger(logLevel string, logContent string) {}
