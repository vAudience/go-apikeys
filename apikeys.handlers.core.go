// Package apikeys provides API key authentication and management middleware for Go applications.
//
// This file contains framework-agnostic handler core logic.
// Following clean architecture, handlers delegate to services and return structured results.
package apikeys

import (
	"context"
	"encoding/json"
	"net/http"

	"go.uber.org/zap"
)

// HandlerResult represents a framework-agnostic handler response
type HandlerResult struct {
	StatusCode int
	Data       interface{}
	Error      string
}

// NewSuccessResult creates a success result
func NewSuccessResult(statusCode int, data interface{}) *HandlerResult {
	return &HandlerResult{
		StatusCode: statusCode,
		Data:       data,
	}
}

// NewErrorResult creates an error result
func NewErrorResult(statusCode int, message string) *HandlerResult {
	return &HandlerResult{
		StatusCode: statusCode,
		Error:      message,
	}
}

// HandlerCore contains framework-agnostic handler logic
type HandlerCore struct {
	manager *APIKeyManager
}

// NewHandlerCore creates a new handler core
func NewHandlerCore(manager *APIKeyManager) *HandlerCore {
	return &HandlerCore{manager: manager}
}

// HandleCreateAPIKey handles API key creation (framework-agnostic)
func (h *HandlerCore) HandleCreateAPIKey(ctx context.Context, requestBody []byte, apiKeyInfo *APIKeyInfo) *HandlerResult {
	// Check system admin authorization
	if apiKeyInfo == nil {
		return NewErrorResult(http.StatusUnauthorized, ERROR_UNAUTHORIZED_NOT_SYSTEM_ADMIN)
	}

	// Validate API key is from a system admin
	if !h.isSystemAdmin(apiKeyInfo) {
		return NewErrorResult(http.StatusUnauthorized, ERROR_UNAUTHORIZED_NOT_SYSTEM_ADMIN)
	}

	// Parse request body
	var newKeyInfo APIKeyInfo
	if err := json.Unmarshal(requestBody, &newKeyInfo); err != nil {
		h.manager.logger.Warn(LOG_MSG_INVALID_JSON,
			zap.Error(err))
		return NewErrorResult(http.StatusBadRequest, ERROR_INVALID_JSON)
	}

	// Create API key via service
	createdKey, err := h.manager.CreateAPIKey(ctx, &newKeyInfo)
	if err != nil {
		h.manager.logger.Error(LOG_MSG_CREATE_APIKEY_FAILED,
			zap.String(LOG_FIELD_USER_ID, newKeyInfo.UserID),
			zap.Error(err))
		return NewErrorResult(http.StatusInternalServerError, ERROR_CREATE_APIKEY_FAILED)
	}

	// Filter response (remove sensitive data)
	callerInfo := createdKey.Filter(true, false)

	h.manager.logger.Info(LOG_MSG_APIKEY_CREATED,
		zap.String(LOG_FIELD_USER_ID, callerInfo.UserID),
		zap.String(LOG_FIELD_HINT, callerInfo.APIKeyHint))

	return NewSuccessResult(http.StatusCreated, callerInfo)
}

// HandleSearchAPIKeys handles API key search (framework-agnostic)
func (h *HandlerCore) HandleSearchAPIKeys(ctx context.Context, apiKeyInfo *APIKeyInfo) *HandlerResult {
	// Check system admin authorization
	if !h.isSystemAdmin(apiKeyInfo) {
		return NewErrorResult(http.StatusUnauthorized, ERROR_UNAUTHORIZED_NOT_SYSTEM_ADMIN)
	}

	// Search via service
	apiKeyInfos, _, err := h.manager.SearchAPIKeys(ctx, DEFAULT_QUERY_OFFSET, DEFAULT_QUERY_LIMIT)
	if err != nil {
		h.manager.logger.Error(LOG_MSG_SEARCH_APIKEYS_FAILED,
			zap.Error(err))
		return NewErrorResult(http.StatusInternalServerError, ERROR_SEARCH_APIKEYS_FAILED)
	}

	return NewSuccessResult(http.StatusOK, apiKeyInfos)
}

// HandleGetAPIKey handles retrieving a single API key (framework-agnostic)
func (h *HandlerCore) HandleGetAPIKey(ctx context.Context, keyOrHash string, apiKeyInfo *APIKeyInfo) *HandlerResult {
	// Check system admin authorization
	if !h.isSystemAdmin(apiKeyInfo) {
		return NewErrorResult(http.StatusUnauthorized, ERROR_UNAUTHORIZED_NOT_SYSTEM_ADMIN)
	}

	// Validate input
	if keyOrHash == "" {
		return NewErrorResult(http.StatusBadRequest, ERROR_MISSING_APIKEY_OR_HASH)
	}

	// Get via service
	retrievedKey, err := h.manager.GetAPIKeyInfo(ctx, keyOrHash)
	if err != nil {
		if err == ErrAPIKeyNotFound {
			return NewErrorResult(http.StatusNotFound, ERROR_API_KEY_NOT_FOUND)
		}
		h.manager.logger.Error(LOG_MSG_GET_APIKEY_FAILED,
			zap.String(LOG_FIELD_HASH, keyOrHash),
			zap.Error(err))
		return NewErrorResult(http.StatusInternalServerError, ERROR_GET_APIKEY_FAILED)
	}

	return NewSuccessResult(http.StatusOK, retrievedKey)
}

// HandleUpdateAPIKey handles updating an API key (framework-agnostic)
func (h *HandlerCore) HandleUpdateAPIKey(ctx context.Context, keyOrHash string, requestBody []byte, apiKeyInfo *APIKeyInfo) *HandlerResult {
	// Check system admin authorization
	if !h.isSystemAdmin(apiKeyInfo) {
		return NewErrorResult(http.StatusUnauthorized, ERROR_UNAUTHORIZED_NOT_SYSTEM_ADMIN)
	}

	// Validate input
	if keyOrHash == "" {
		return NewErrorResult(http.StatusBadRequest, ERROR_MISSING_APIKEY_HASH)
	}

	// Parse request body
	var updateInfo APIKeyInfo
	if err := json.Unmarshal(requestBody, &updateInfo); err != nil {
		h.manager.logger.Warn(LOG_MSG_INVALID_JSON,
			zap.Error(err))
		return NewErrorResult(http.StatusBadRequest, ERROR_INVALID_JSON)
	}
	updateInfo.APIKeyHash = keyOrHash

	// Update via service
	err := h.manager.UpdateAPIKey(ctx, &updateInfo)
	if err != nil {
		h.manager.logger.Error(LOG_MSG_UPDATE_APIKEY_FAILED,
			zap.String(LOG_FIELD_HASH, keyOrHash),
			zap.Error(err))
		return NewErrorResult(http.StatusInternalServerError, ERROR_UPDATE_APIKEY_FAILED)
	}

	// Retrieve updated key
	updatedKey, err := h.manager.GetAPIKeyInfo(ctx, keyOrHash)
	if err != nil {
		h.manager.logger.Error(LOG_MSG_GET_APIKEY_FAILED,
			zap.String(LOG_FIELD_HASH, keyOrHash),
			zap.Error(err))
		return NewErrorResult(http.StatusInternalServerError, ERROR_GET_APIKEY_FAILED)
	}

	return NewSuccessResult(http.StatusOK, updatedKey)
}

// HandleDeleteAPIKey handles deleting an API key (framework-agnostic)
func (h *HandlerCore) HandleDeleteAPIKey(ctx context.Context, keyOrHash string, apiKeyInfo *APIKeyInfo) *HandlerResult {
	// Check system admin authorization
	if !h.isSystemAdmin(apiKeyInfo) {
		return NewErrorResult(http.StatusUnauthorized, ERROR_UNAUTHORIZED_NOT_SYSTEM_ADMIN)
	}

	// Validate input
	if keyOrHash == "" {
		return NewErrorResult(http.StatusBadRequest, ERROR_MISSING_APIKEY_OR_HASH)
	}

	// Delete via service
	err := h.manager.DeleteAPIKey(ctx, keyOrHash)
	if err != nil {
		if err == ErrAPIKeyNotFound {
			return NewErrorResult(http.StatusNotFound, ERROR_API_KEY_NOT_FOUND)
		}
		h.manager.logger.Error(LOG_MSG_DELETE_APIKEY_FAILED,
			zap.String(LOG_FIELD_HASH, keyOrHash),
			zap.Error(err))
		return NewErrorResult(http.StatusInternalServerError, ERROR_DELETE_APIKEY_FAILED)
	}

	return NewSuccessResult(http.StatusNoContent, nil)
}

// HandleIsSystemAdmin checks if the API key is a system admin (framework-agnostic)
func (h *HandlerCore) HandleIsSystemAdmin(apiKeyInfo *APIKeyInfo) *HandlerResult {
	isAdmin := h.isSystemAdmin(apiKeyInfo)
	return NewSuccessResult(http.StatusOK, map[string]bool{RESPONSE_KEY_IS_SYSTEM_ADMIN: isAdmin})
}

// isSystemAdmin is a helper to check system admin status
func (h *HandlerCore) isSystemAdmin(apiKeyInfo *APIKeyInfo) bool {
	if apiKeyInfo == nil {
		return false
	}
	return h.manager.service.IsSystemAdmin(apiKeyInfo)
}
