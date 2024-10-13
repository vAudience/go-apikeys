package apikeys

import (
	"context"
	"net/http"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp/fasthttpadaptor"
)

type FiberFramework struct{}

func (f *FiberFramework) GetRequestHeader(r interface{}, key string) string {
	return r.(*fiber.Ctx).Get(key)
}

func (f *FiberFramework) SetResponseHeader(w interface{}, key, value string) {
	w.(*fiber.Ctx).Set(key, value)
}

func (f *FiberFramework) GetRequestParam(r interface{}, key string) string {
	return r.(*fiber.Ctx).Params(key)
}

func (f *FiberFramework) WriteResponse(w interface{}, status int, body []byte) error {
	return w.(*fiber.Ctx).Status(status).Send(body)
}

func (f *FiberFramework) GetRequestContext(r interface{}) context.Context {
	return r.(*fiber.Ctx).UserContext()
}

func (f *FiberFramework) SetContextValue(r interface{}, key, value interface{}) {
	ctx := r.(*fiber.Ctx)
	newCtx := context.WithValue(ctx.UserContext(), key, value)
	ctx.SetUserContext(newCtx)
}

func (f *FiberFramework) GetContextValue(r interface{}, key interface{}) interface{} {
	return r.(*fiber.Ctx).UserContext().Value(key)
}

func (f *FiberFramework) GetRequestPath(r interface{}) string {
	return r.(*fiber.Ctx).Path()
}

func (f *FiberFramework) WrapMiddleware(next http.HandlerFunc) interface{} {
	return func(c *fiber.Ctx) error {
		handler := fasthttpadaptor.NewFastHTTPHandlerFunc(next)
		handler(c.Context())
		return nil
	}
}
