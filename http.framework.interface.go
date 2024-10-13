package apikeys

import (
	"context"
	"net/http"
)

// HTTPFramework defines the interface for HTTP framework compatibility
type HTTPFramework interface {
	// GetRequestHeader retrieves a header value from the request
	GetRequestHeader(r interface{}, key string) string

	// SetResponseHeader sets a header in the response
	SetResponseHeader(w interface{}, key, value string)

	// GetRequestParam retrieves a parameter from the request (e.g., path or query param)
	GetRequestParam(r interface{}, key string) string

	// WriteResponse writes the response body
	WriteResponse(w interface{}, status int, body []byte) error

	// GetRequestContext retrieves the context from the request
	GetRequestContext(r interface{}) context.Context

	// SetContextValue sets a value in the request context
	SetContextValue(r interface{}, key, value interface{})

	// GetContextValue retrieves a value from the request context
	GetContextValue(r interface{}, key interface{}) interface{}

	// WrapMiddleware wraps a middleware function to be compatible with the framework
	WrapMiddleware(next http.HandlerFunc) interface{}

	// GetRequestPath retrieves the path from the request
	GetRequestPath(r interface{}) string
}
