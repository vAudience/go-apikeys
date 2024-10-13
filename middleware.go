// github.com/vaudience/go-apikeys/middleware.go
package apikeys

import (
	"fmt"
	"net/http"
	"regexp"
)

func (m *APIKeyManager) Middleware() interface{} {
	return m.framework.WrapMiddleware(func(w http.ResponseWriter, r *http.Request) {
		for _, pattern := range m.config.IgnoreApiKeyForRoutePatterns {
			ok, _ := regexp.MatchString(pattern, m.framework.GetRequestPath(r))
			if ok {
				m.logger("DEBUG", fmt.Sprintf("Ignoring API key for route: (%s)", m.framework.GetRequestPath(r)))
				return
			}
		}

		apiKey := m.framework.GetRequestHeader(r, m.config.HeaderKey)
		apiKeyInfo, err := m.GetAPIKeyInfo(r.Context(), apiKey)
		if err != nil {
			if err == ErrAPIKeyNotFound {
				m.framework.WriteResponse(w, http.StatusUnauthorized, []byte(ErrInvalidAPIKey.Error()))
				return
			}
			m.framework.WriteResponse(w, http.StatusUnauthorized, []byte(ErrFailedToRetrieveAPIKeyInfo.Error()))
			return
		}

		if m.config.EnableRateLimit {
			allowed, err := m.limiter.Allow(r.Context(), m.framework, r)
			if err != nil {
				m.framework.WriteResponse(w, http.StatusInternalServerError, []byte(ErrFailedToCheckRateLimit.Error()))
				return
			}
			if !allowed {
				m.framework.WriteResponse(w, http.StatusTooManyRequests, []byte(ErrRateLimitExceeded.Error()))
				return
			}
		}

		m.framework.SetContextValue(r, LOCALS_KEY_APIKEYS, apiKeyInfo)
	})
}
