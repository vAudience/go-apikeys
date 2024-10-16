package apikeys

import (
	"context"
)

// HTTPFramework defines the interface for HTTP framework compatibility

type HTTPFramework interface {
	GetRequestHeader(r interface{}, key string) string
	SetResponseHeader(w interface{}, key, value string)
	GetRequestParam(r interface{}, key string) string
	WriteResponse(w interface{}, status int, body []byte) error
	GetRequestContext(r interface{}) context.Context
	SetContextValue(r interface{}, key, value interface{})
	GetContextValue(r interface{}, key interface{}) interface{}
	GetRequestPath(r interface{}) string
	WrapMiddleware(next interface{}) interface{}
}
