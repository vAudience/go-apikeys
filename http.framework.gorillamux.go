package apikeys

import (
	"context"
	"net/http"

	"github.com/gorilla/mux"
)

type GorillaMuxFramework struct{}

func (g *GorillaMuxFramework) GetRequestHeader(r interface{}, key string) string {
	return r.(*http.Request).Header.Get(key)
}

func (g *GorillaMuxFramework) SetResponseHeader(w interface{}, key, value string) {
	if rw, ok := w.(http.ResponseWriter); ok {
		rw.Header().Set(key, value)
	}
}

func (g *GorillaMuxFramework) GetRequestParam(r interface{}, key string) string {
	return mux.Vars(r.(*http.Request))[key]
}

func (g *GorillaMuxFramework) WriteResponse(w interface{}, status int, body []byte) error {
	if rw, ok := w.(http.ResponseWriter); ok {
		rw.WriteHeader(status)
		_, err := rw.Write(body)
		return err
	}
	return nil
}

func (g *GorillaMuxFramework) GetRequestContext(r interface{}) context.Context {
	return r.(*http.Request).Context()
}

func (g *GorillaMuxFramework) SetContextValue(r interface{}, key, value interface{}) {
	req := r.(*http.Request)
	*req = *req.WithContext(context.WithValue(req.Context(), key, value))
}

func (g *GorillaMuxFramework) GetContextValue(r interface{}, key interface{}) interface{} {
	return r.(*http.Request).Context().Value(key)
}

func (g *GorillaMuxFramework) GetRequestPath(r interface{}) string {
	return r.(*http.Request).URL.Path
}

func (g *GorillaMuxFramework) WrapMiddleware(next http.HandlerFunc) interface{} {
	return func(w http.ResponseWriter, r *http.Request) {
		next(w, r)
	}
}
