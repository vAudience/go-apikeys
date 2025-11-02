package apikeys

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"

	"github.com/itsatony/go-datarepository"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Mock DataRepository for Rate Limiter Tests
// =============================================================================

type mockRateLimitRepo struct {
	incrementCount   int64
	incrementError   error
	readValue        int64
	readError        error
	setExpirationErr error
	callLog          []string // Track method calls for assertions
}

func newMockRateLimitRepo() *mockRateLimitRepo {
	return &mockRateLimitRepo{
		callLog: []string{},
	}
}

func (m *mockRateLimitRepo) AtomicIncrement(ctx context.Context, id datarepository.EntityIdentifier) (int64, error) {
	m.callLog = append(m.callLog, "AtomicIncrement")
	if m.incrementError != nil {
		return 0, m.incrementError
	}
	m.incrementCount++
	return m.incrementCount, nil
}

func (m *mockRateLimitRepo) SetExpiration(ctx context.Context, id datarepository.EntityIdentifier, expiration time.Duration) error {
	m.callLog = append(m.callLog, "SetExpiration")
	return m.setExpirationErr
}

func (m *mockRateLimitRepo) Read(ctx context.Context, id datarepository.EntityIdentifier, entity interface{}) error {
	m.callLog = append(m.callLog, "Read")
	if m.readError != nil {
		return m.readError
	}
	// Type assert to *int64 and set value
	if ptr, ok := entity.(*int64); ok {
		*ptr = m.readValue
	}
	return nil
}

// Stub methods to satisfy DataRepository interface
func (m *mockRateLimitRepo) Create(ctx context.Context, id datarepository.EntityIdentifier, entity interface{}) error {
	return nil
}
func (m *mockRateLimitRepo) Upsert(ctx context.Context, id datarepository.EntityIdentifier, entity interface{}) error {
	return nil
}
func (m *mockRateLimitRepo) Update(ctx context.Context, id datarepository.EntityIdentifier, entity interface{}) error {
	return nil
}
func (m *mockRateLimitRepo) Delete(ctx context.Context, id datarepository.EntityIdentifier) error {
	return nil
}
func (m *mockRateLimitRepo) List(ctx context.Context, pattern string) ([]datarepository.EntityIdentifier, []interface{}, error) {
	return nil, nil, nil
}
func (m *mockRateLimitRepo) Search(ctx context.Context, query string, offset, limit int, sortBy, sortDir string) ([]datarepository.EntityIdentifier, error) {
	return nil, nil
}
func (m *mockRateLimitRepo) AcquireLock(ctx context.Context, id datarepository.EntityIdentifier, ttl time.Duration) (bool, error) {
	return true, nil
}
func (m *mockRateLimitRepo) ReleaseLock(ctx context.Context, id datarepository.EntityIdentifier) error {
	return nil
}
func (m *mockRateLimitRepo) Close() error {
	return nil
}
func (m *mockRateLimitRepo) Publish(ctx context.Context, channel string, message interface{}) error {
	return nil
}
func (m *mockRateLimitRepo) Subscribe(ctx context.Context, channel string) (chan interface{}, error) {
	ch := make(chan interface{})
	close(ch)
	return ch, nil
}
func (m *mockRateLimitRepo) Ping(ctx context.Context) error {
	return nil
}
func (m *mockRateLimitRepo) GetExpiration(ctx context.Context, id datarepository.EntityIdentifier) (time.Duration, error) {
	return 0, nil
}
func (m *mockRateLimitRepo) RegisterPlugin(plugin datarepository.RepositoryPlugin) error {
	return nil
}
func (m *mockRateLimitRepo) GetPlugin(name string) (datarepository.RepositoryPlugin, bool) {
	return nil, false
}

// =============================================================================
// Mock HTTPFramework for Rate Limiter Tests
// =============================================================================

type mockFrameworkForRateLimit struct {
	requestPath   string
	contextValues map[interface{}]interface{}
}

func newMockFrameworkForRateLimit() *mockFrameworkForRateLimit {
	return &mockFrameworkForRateLimit{
		contextValues: make(map[interface{}]interface{}),
	}
}

func (m *mockFrameworkForRateLimit) GetRequestPath(req interface{}) string {
	return m.requestPath
}

func (m *mockFrameworkForRateLimit) GetContextValue(req interface{}, key interface{}) interface{} {
	return m.contextValues[key]
}

// Stub methods to satisfy HTTPFramework interface
func (m *mockFrameworkForRateLimit) SetContextValue(req interface{}, key interface{}, value interface{}) {}
func (m *mockFrameworkForRateLimit) GetRequestHeader(r interface{}, key string) string {
	return ""
}
func (m *mockFrameworkForRateLimit) SetResponseHeader(w interface{}, key, value string) {}
func (m *mockFrameworkForRateLimit) GetRequestParam(r interface{}, key string) string {
	return ""
}
func (m *mockFrameworkForRateLimit) WriteResponse(w interface{}, status int, body []byte) error {
	return nil
}
func (m *mockFrameworkForRateLimit) GetRequestContext(r interface{}) context.Context {
	return context.Background()
}
func (m *mockFrameworkForRateLimit) WrapMiddleware(next interface{}) interface{} {
	return nil
}

// =============================================================================
// NewRateLimiter Tests (3 tests)
// =============================================================================

func TestNewRateLimiter(t *testing.T) {
	t.Run("creates limiter with valid rules", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		rules := []RateLimitRule{
			{
				Path:     "/api/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetAPIKey},
			},
		}

		limiter := NewRateLimiter(repo, rules)

		assert.NotNil(t, limiter)
		assert.Equal(t, repo, limiter.repo)
		assert.Len(t, limiter.rules, 1)
	})

	t.Run("compiles regex patterns correctly", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		rules := []RateLimitRule{
			{
				Path:     "/api/users/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetAPIKey},
			},
			{
				Path:     "/api/admin/.*",
				Timespan: time.Hour,
				Limit:    100,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetUserID},
			},
		}

		limiter := NewRateLimiter(repo, rules)

		assert.NotNil(t, limiter.rules[0].pathRegex)
		assert.NotNil(t, limiter.rules[1].pathRegex)
		assert.True(t, limiter.rules[0].pathRegex.MatchString("/api/users/123"))
		assert.False(t, limiter.rules[0].pathRegex.MatchString("/api/admin/123"))
		assert.True(t, limiter.rules[1].pathRegex.MatchString("/api/admin/settings"))
	})

	t.Run("handles empty rules", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		rules := []RateLimitRule{}

		limiter := NewRateLimiter(repo, rules)

		assert.NotNil(t, limiter)
		assert.Empty(t, limiter.rules)
	})
}

// =============================================================================
// Allow() Tests (20 tests)
// =============================================================================

func TestRateLimiter_Allow(t *testing.T) {
	t.Run("allow when no rules match path", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		rules := []RateLimitRule{
			{
				Path:     "/api/admin/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetAPIKey},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.requestPath = "/api/public/health"

		ctx := context.Background()
		allowed, err := limiter.Allow(ctx, framework, nil)

		assert.NoError(t, err)
		assert.True(t, allowed)
		assert.Empty(t, repo.callLog) // No rate limit checks performed
	})

	t.Run("allow within rate limit - APIKey target", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementCount = 0 // Will return 1 on first increment
		rules := []RateLimitRule{
			{
				Path:     "/api/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetAPIKey},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.requestPath = "/api/users"
		framework.contextValues[LOCALS_KEY_APIKEYS] = &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "user-1",
			OrgID:      "org-1",
		}

		ctx := context.Background()
		allowed, err := limiter.Allow(ctx, framework, nil)

		assert.NoError(t, err)
		assert.True(t, allowed)
		assert.Contains(t, repo.callLog, "AtomicIncrement")
		assert.Contains(t, repo.callLog, "SetExpiration")
	})

	t.Run("block when rate limit exceeded - APIKey target", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementCount = 11 // Exceeds limit of 10
		rules := []RateLimitRule{
			{
				Path:     "/api/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetAPIKey},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.requestPath = "/api/users"
		framework.contextValues[LOCALS_KEY_APIKEYS] = &APIKeyInfo{
			APIKeyHash: "test-hash",
		}

		ctx := context.Background()
		allowed, err := limiter.Allow(ctx, framework, nil)

		assert.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("allow within rate limit - UserID target", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementCount = 0
		rules := []RateLimitRule{
			{
				Path:     "/api/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetUserID},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.requestPath = "/api/users"
		framework.contextValues[LOCALS_KEY_APIKEYS] = &APIKeyInfo{
			UserID: "user-1",
		}

		ctx := context.Background()
		allowed, err := limiter.Allow(ctx, framework, nil)

		assert.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("allow within rate limit - OrgID target", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementCount = 0
		rules := []RateLimitRule{
			{
				Path:     "/api/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetOrgID},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.requestPath = "/api/users"
		framework.contextValues[LOCALS_KEY_APIKEYS] = &APIKeyInfo{
			OrgID: "org-1",
		}

		ctx := context.Background()
		allowed, err := limiter.Allow(ctx, framework, nil)

		assert.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("multiple ApplyTo targets all must pass", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementCount = 0
		rules := []RateLimitRule{
			{
				Path:     "/api/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo: []RateLimitRuleTarget{
					RateLimitRuleTargetAPIKey,
					RateLimitRuleTargetUserID,
					RateLimitRuleTargetOrgID,
				},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.requestPath = "/api/users"
		framework.contextValues[LOCALS_KEY_APIKEYS] = &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "user-1",
			OrgID:      "org-1",
		}

		ctx := context.Background()
		allowed, err := limiter.Allow(ctx, framework, nil)

		assert.NoError(t, err)
		assert.True(t, allowed)
		// Should have called AtomicIncrement 3 times (once per target)
		count := 0
		for _, call := range repo.callLog {
			if call == "AtomicIncrement" {
				count++
			}
		}
		assert.Equal(t, 3, count)
	})

	t.Run("multiple ApplyTo targets - first fails blocks request", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		// First increment returns 11 (exceeds limit), others would pass
		repo.incrementCount = 10
		rules := []RateLimitRule{
			{
				Path:     "/api/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo: []RateLimitRuleTarget{
					RateLimitRuleTargetAPIKey,
					RateLimitRuleTargetUserID,
				},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.requestPath = "/api/users"
		framework.contextValues[LOCALS_KEY_APIKEYS] = &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "user-1",
		}

		ctx := context.Background()
		allowed, err := limiter.Allow(ctx, framework, nil)

		assert.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("multiple rules - all must match and pass", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementCount = 0
		rules := []RateLimitRule{
			{
				Path:     "/api/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetAPIKey},
			},
			{
				Path:     "/api/users/.*",
				Timespan: time.Hour,
				Limit:    100,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetUserID},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.requestPath = "/api/users/123"
		framework.contextValues[LOCALS_KEY_APIKEYS] = &APIKeyInfo{
			APIKeyHash: "test-hash",
			UserID:     "user-1",
		}

		ctx := context.Background()
		allowed, err := limiter.Allow(ctx, framework, nil)

		assert.NoError(t, err)
		assert.True(t, allowed)
		// Should have called AtomicIncrement twice (once per matching rule)
		count := 0
		for _, call := range repo.callLog {
			if call == "AtomicIncrement" {
				count++
			}
		}
		assert.Equal(t, 2, count)
	})

	t.Run("path regex matching works correctly", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementCount = 0
		rules := []RateLimitRule{
			{
				Path:     "^/api/v[0-9]+/users$",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetAPIKey},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.contextValues[LOCALS_KEY_APIKEYS] = &APIKeyInfo{APIKeyHash: "hash"}
		ctx := context.Background()

		// Should match
		framework.requestPath = "/api/v1/users"
		allowed, err := limiter.Allow(ctx, framework, nil)
		assert.NoError(t, err)
		assert.True(t, allowed)

		// Should not match
		framework.requestPath = "/api/v1/users/123"
		repo.callLog = []string{} // Reset log
		allowed, err = limiter.Allow(ctx, framework, nil)
		assert.NoError(t, err)
		assert.True(t, allowed)
		assert.Empty(t, repo.callLog) // No rate limit checks
	})

	t.Run("missing API key info in context returns error - APIKey target", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		rules := []RateLimitRule{
			{
				Path:     "/api/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetAPIKey},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.requestPath = "/api/users"
		// No API key info in context

		ctx := context.Background()
		allowed, err := limiter.Allow(ctx, framework, nil)

		assert.Error(t, err)
		assert.False(t, allowed)
		assert.Contains(t, err.Error(), "API key info not found in context")
	})

	t.Run("missing API key info in context returns error - UserID target", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		rules := []RateLimitRule{
			{
				Path:     "/api/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetUserID},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.requestPath = "/api/users"

		ctx := context.Background()
		allowed, err := limiter.Allow(ctx, framework, nil)

		assert.Error(t, err)
		assert.False(t, allowed)
		assert.Contains(t, err.Error(), "API key info not found in context")
	})

	t.Run("missing API key info in context returns error - OrgID target", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		rules := []RateLimitRule{
			{
				Path:     "/api/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetOrgID},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.requestPath = "/api/users"

		ctx := context.Background()
		allowed, err := limiter.Allow(ctx, framework, nil)

		assert.Error(t, err)
		assert.False(t, allowed)
		assert.Contains(t, err.Error(), "API key info not found in context")
	})

	t.Run("invalid API key info type in context returns error", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		rules := []RateLimitRule{
			{
				Path:     "/api/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetAPIKey},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.requestPath = "/api/users"
		framework.contextValues[LOCALS_KEY_APIKEYS] = "invalid-type"

		ctx := context.Background()
		allowed, err := limiter.Allow(ctx, framework, nil)

		assert.Error(t, err)
		assert.False(t, allowed)
		assert.Contains(t, err.Error(), "invalid API key info type")
	})

	t.Run("nil API key info in context returns error", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		rules := []RateLimitRule{
			{
				Path:     "/api/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetAPIKey},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.requestPath = "/api/users"
		framework.contextValues[LOCALS_KEY_APIKEYS] = (*APIKeyInfo)(nil)

		ctx := context.Background()
		allowed, err := limiter.Allow(ctx, framework, nil)

		assert.Error(t, err)
		assert.False(t, allowed)
		assert.Contains(t, err.Error(), "invalid API key info type")
	})

	t.Run("repository AtomicIncrement error propagates", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementError = errors.New("redis connection failed")
		rules := []RateLimitRule{
			{
				Path:     "/api/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetAPIKey},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.requestPath = "/api/users"
		framework.contextValues[LOCALS_KEY_APIKEYS] = &APIKeyInfo{APIKeyHash: "hash"}

		ctx := context.Background()
		allowed, err := limiter.Allow(ctx, framework, nil)

		assert.Error(t, err)
		assert.False(t, allowed)
		assert.Contains(t, err.Error(), "redis connection failed")
	})

	t.Run("repository SetExpiration error propagates on first request", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementCount = 0 // First request
		repo.setExpirationErr = errors.New("failed to set TTL")
		rules := []RateLimitRule{
			{
				Path:     "/api/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetAPIKey},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.requestPath = "/api/users"
		framework.contextValues[LOCALS_KEY_APIKEYS] = &APIKeyInfo{APIKeyHash: "hash"}

		ctx := context.Background()
		allowed, err := limiter.Allow(ctx, framework, nil)

		assert.Error(t, err)
		assert.False(t, allowed)
		assert.Contains(t, err.Error(), "failed to set expiration")
	})

	t.Run("ignores unknown ApplyTo target types", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementCount = 0
		rules := []RateLimitRule{
			{
				Path:     "/api/.*",
				Timespan: time.Minute,
				Limit:    10,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTarget("unknown-target")},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.requestPath = "/api/users"
		framework.contextValues[LOCALS_KEY_APIKEYS] = &APIKeyInfo{APIKeyHash: "hash"}

		ctx := context.Background()
		allowed, err := limiter.Allow(ctx, framework, nil)

		// Should allow since unknown target is ignored
		assert.NoError(t, err)
		assert.True(t, allowed)
		assert.Empty(t, repo.callLog) // No rate limit checks performed
	})

	t.Run("sequential requests increment counter correctly", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementCount = 0
		rules := []RateLimitRule{
			{
				Path:     "/api/.*",
				Timespan: time.Minute,
				Limit:    3,
				ApplyTo:  []RateLimitRuleTarget{RateLimitRuleTargetAPIKey},
			},
		}
		limiter := NewRateLimiter(repo, rules)

		framework := newMockFrameworkForRateLimit()
		framework.requestPath = "/api/users"
		framework.contextValues[LOCALS_KEY_APIKEYS] = &APIKeyInfo{APIKeyHash: "hash"}

		ctx := context.Background()

		// Request 1 - should pass (count = 1)
		allowed, err := limiter.Allow(ctx, framework, nil)
		assert.NoError(t, err)
		assert.True(t, allowed)
		assert.Equal(t, int64(1), repo.incrementCount)

		// Request 2 - should pass (count = 2)
		allowed, err = limiter.Allow(ctx, framework, nil)
		assert.NoError(t, err)
		assert.True(t, allowed)
		assert.Equal(t, int64(2), repo.incrementCount)

		// Request 3 - should pass (count = 3)
		allowed, err = limiter.Allow(ctx, framework, nil)
		assert.NoError(t, err)
		assert.True(t, allowed)
		assert.Equal(t, int64(3), repo.incrementCount)

		// Request 4 - should be blocked (count = 4 > limit 3)
		allowed, err = limiter.Allow(ctx, framework, nil)
		assert.NoError(t, err)
		assert.False(t, allowed)
		assert.Equal(t, int64(4), repo.incrementCount)
	})
}

// =============================================================================
// checkRateLimit Tests (7 tests)
// =============================================================================

func TestRateLimiter_checkRateLimit(t *testing.T) {
	t.Run("first request sets expiration", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementCount = 0 // Will return 1
		limiter := &RateLimiter{repo: repo}

		ctx := context.Background()
		allowed, err := limiter.checkRateLimit(ctx, "test-key", time.Minute, 10)

		assert.NoError(t, err)
		assert.True(t, allowed)
		assert.Contains(t, repo.callLog, "AtomicIncrement")
		assert.Contains(t, repo.callLog, "SetExpiration")
		assert.Equal(t, int64(1), repo.incrementCount)
	})

	t.Run("subsequent requests do not set expiration", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementCount = 5 // Not first request
		limiter := &RateLimiter{repo: repo}

		ctx := context.Background()
		allowed, err := limiter.checkRateLimit(ctx, "test-key", time.Minute, 10)

		assert.NoError(t, err)
		assert.True(t, allowed)
		assert.Contains(t, repo.callLog, "AtomicIncrement")
		assert.NotContains(t, repo.callLog, "SetExpiration")
	})

	t.Run("limit not exceeded allows request", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementCount = 9 // Under limit of 10
		limiter := &RateLimiter{repo: repo}

		ctx := context.Background()
		allowed, err := limiter.checkRateLimit(ctx, "test-key", time.Minute, 10)

		assert.NoError(t, err)
		assert.True(t, allowed)
	})

	t.Run("limit exceeded blocks request", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementCount = 11 // Over limit of 10
		limiter := &RateLimiter{repo: repo}

		ctx := context.Background()
		allowed, err := limiter.checkRateLimit(ctx, "test-key", time.Minute, 10)

		assert.NoError(t, err)
		assert.False(t, allowed)
	})

	t.Run("limit exactly met allows request", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementCount = 9 // Will become 10 after increment (exactly at limit)
		limiter := &RateLimiter{repo: repo}

		ctx := context.Background()
		allowed, err := limiter.checkRateLimit(ctx, "test-key", time.Minute, 10)

		assert.NoError(t, err)
		assert.True(t, allowed)
		assert.Equal(t, int64(10), repo.incrementCount)
	})

	t.Run("AtomicIncrement error propagates", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementError = errors.New("increment failed")
		limiter := &RateLimiter{repo: repo}

		ctx := context.Background()
		allowed, err := limiter.checkRateLimit(ctx, "test-key", time.Minute, 10)

		assert.Error(t, err)
		assert.False(t, allowed)
		assert.Contains(t, err.Error(), "failed to increment rate limit counter")
	})

	t.Run("SetExpiration error propagates", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.incrementCount = 0 // First request
		repo.setExpirationErr = errors.New("set TTL failed")
		limiter := &RateLimiter{repo: repo}

		ctx := context.Background()
		allowed, err := limiter.checkRateLimit(ctx, "test-key", time.Minute, 10)

		assert.Error(t, err)
		assert.False(t, allowed)
		assert.Contains(t, err.Error(), "failed to set expiration")
	})
}

// =============================================================================
// GetCurrentValueByAPIKeyInfo Tests (8 tests)
// =============================================================================

func TestRateLimiter_GetCurrentValueByAPIKeyInfo(t *testing.T) {
	t.Run("gets value for matching rule - APIKey target", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.readValue = 5
		rules := []RateLimitRule{
			{
				Path:      "/api/.*",
				pathRegex: regexp.MustCompile("/api/.*"),
				ApplyTo:   []RateLimitRuleTarget{RateLimitRuleTargetAPIKey},
			},
		}
		limiter := &RateLimiter{repo: repo, rules: rules}

		ctx := context.Background()
		apiKeyInfo := &APIKeyInfo{APIKeyHash: "test-hash"}
		value, err := limiter.GetCurrentValueByAPIKeyInfo(ctx, apiKeyInfo, "/api/.*")

		assert.NoError(t, err)
		assert.Equal(t, int64(5), value)
		assert.Contains(t, repo.callLog, "Read")
	})

	t.Run("gets value for matching rule - UserID target", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.readValue = 7
		rules := []RateLimitRule{
			{
				Path:      "/api/.*",
				pathRegex: regexp.MustCompile("/api/.*"),
				ApplyTo:   []RateLimitRuleTarget{RateLimitRuleTargetUserID},
			},
		}
		limiter := &RateLimiter{repo: repo, rules: rules}

		ctx := context.Background()
		apiKeyInfo := &APIKeyInfo{UserID: "user-1"}
		value, err := limiter.GetCurrentValueByAPIKeyInfo(ctx, apiKeyInfo, "/api/.*")

		assert.NoError(t, err)
		assert.Equal(t, int64(7), value)
	})

	t.Run("gets value for matching rule - OrgID target", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.readValue = 3
		rules := []RateLimitRule{
			{
				Path:      "/api/.*",
				pathRegex: regexp.MustCompile("/api/.*"),
				ApplyTo:   []RateLimitRuleTarget{RateLimitRuleTargetOrgID},
			},
		}
		limiter := &RateLimiter{repo: repo, rules: rules}

		ctx := context.Background()
		apiKeyInfo := &APIKeyInfo{OrgID: "org-1"}
		value, err := limiter.GetCurrentValueByAPIKeyInfo(ctx, apiKeyInfo, "/api/.*")

		assert.NoError(t, err)
		assert.Equal(t, int64(3), value)
	})

	t.Run("returns 0 for no matching rule", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		rules := []RateLimitRule{
			{
				Path:      "/api/users/.*",
				pathRegex: regexp.MustCompile("/api/users/.*"),
				ApplyTo:   []RateLimitRuleTarget{RateLimitRuleTargetAPIKey},
			},
		}
		limiter := &RateLimiter{repo: repo, rules: rules}

		ctx := context.Background()
		apiKeyInfo := &APIKeyInfo{APIKeyHash: "test-hash"}
		value, err := limiter.GetCurrentValueByAPIKeyInfo(ctx, apiKeyInfo, "/api/admin/.*")

		assert.NoError(t, err)
		assert.Equal(t, int64(0), value)
		assert.Empty(t, repo.callLog) // No repository calls
	})

	t.Run("multiple targets returns first value", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.readValue = 10
		rules := []RateLimitRule{
			{
				Path:      "/api/.*",
				pathRegex: regexp.MustCompile("/api/.*"),
				ApplyTo: []RateLimitRuleTarget{
					RateLimitRuleTargetAPIKey,
					RateLimitRuleTargetUserID,
				},
			},
		}
		limiter := &RateLimiter{repo: repo, rules: rules}

		ctx := context.Background()
		apiKeyInfo := &APIKeyInfo{
			APIKeyHash: "hash",
			UserID:     "user",
		}
		value, err := limiter.GetCurrentValueByAPIKeyInfo(ctx, apiKeyInfo, "/api/.*")

		assert.NoError(t, err)
		assert.Equal(t, int64(10), value) // First target's value
	})

	t.Run("ignores unknown target types", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		rules := []RateLimitRule{
			{
				Path:      "/api/.*",
				pathRegex: regexp.MustCompile("/api/.*"),
				ApplyTo:   []RateLimitRuleTarget{RateLimitRuleTarget("unknown")},
			},
		}
		limiter := &RateLimiter{repo: repo, rules: rules}

		ctx := context.Background()
		apiKeyInfo := &APIKeyInfo{APIKeyHash: "hash"}
		value, err := limiter.GetCurrentValueByAPIKeyInfo(ctx, apiKeyInfo, "/api/.*")

		assert.NoError(t, err)
		assert.Equal(t, int64(0), value)
	})

	t.Run("repository error propagates", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.readError = errors.New("read failed")
		rules := []RateLimitRule{
			{
				Path:      "/api/.*",
				pathRegex: regexp.MustCompile("/api/.*"),
				ApplyTo:   []RateLimitRuleTarget{RateLimitRuleTargetAPIKey},
			},
		}
		limiter := &RateLimiter{repo: repo, rules: rules}

		ctx := context.Background()
		apiKeyInfo := &APIKeyInfo{APIKeyHash: "hash"}
		value, err := limiter.GetCurrentValueByAPIKeyInfo(ctx, apiKeyInfo, "/api/.*")

		assert.Error(t, err)
		assert.Equal(t, int64(0), value)
	})

	t.Run("not found returns 0 without error", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.readError = datarepository.ErrNotFound
		rules := []RateLimitRule{
			{
				Path:      "/api/.*",
				pathRegex: regexp.MustCompile("/api/.*"),
				ApplyTo:   []RateLimitRuleTarget{RateLimitRuleTargetAPIKey},
			},
		}
		limiter := &RateLimiter{repo: repo, rules: rules}

		ctx := context.Background()
		apiKeyInfo := &APIKeyInfo{APIKeyHash: "hash"}
		value, err := limiter.GetCurrentValueByAPIKeyInfo(ctx, apiKeyInfo, "/api/.*")

		assert.NoError(t, err)
		assert.Equal(t, int64(0), value)
	})
}

// =============================================================================
// getCurrentValue Tests (3 tests)
// =============================================================================

func TestRateLimiter_getCurrentValue(t *testing.T) {
	t.Run("gets value from repository", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.readValue = 42
		limiter := &RateLimiter{repo: repo}

		ctx := context.Background()
		value, err := limiter.getCurrentValue(ctx, "test-key")

		assert.NoError(t, err)
		assert.Equal(t, int64(42), value)
		assert.Contains(t, repo.callLog, "Read")
	})

	t.Run("not found returns 0", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.readError = datarepository.ErrNotFound
		limiter := &RateLimiter{repo: repo}

		ctx := context.Background()
		value, err := limiter.getCurrentValue(ctx, "test-key")

		assert.NoError(t, err)
		assert.Equal(t, int64(0), value)
	})

	t.Run("repository error propagates", func(t *testing.T) {
		repo := newMockRateLimitRepo()
		repo.readError = errors.New("connection lost")
		limiter := &RateLimiter{repo: repo}

		ctx := context.Background()
		value, err := limiter.getCurrentValue(ctx, "test-key")

		assert.Error(t, err)
		assert.Equal(t, int64(0), value)
		assert.Contains(t, err.Error(), "connection lost")
	})
}

// =============================================================================
// assembleRateLimitKey Tests (2 tests)
// =============================================================================

func TestAssembleRateLimitKey(t *testing.T) {
	t.Run("assembles key correctly", func(t *testing.T) {
		key := assembleRateLimitKey("test-key-123")

		assert.Contains(t, key, RATE_LIMIT_KEY_PREFIX)
		assert.Contains(t, key, RATE_LIMIT_KEY_SEPARATOR)
		assert.Contains(t, key, "test-key-123")
	})

	t.Run("assembles key with different inputs", func(t *testing.T) {
		keys := []string{
			"user-123",
			"org-456",
			"hash-abc",
		}

		for _, input := range keys {
			result := assembleRateLimitKey(input)
			assert.Contains(t, result, RATE_LIMIT_KEY_PREFIX)
			assert.Contains(t, result, input)
			// Verify format: prefix + separator + input
			expected := RATE_LIMIT_KEY_PREFIX + RATE_LIMIT_KEY_SEPARATOR + input
			assert.Equal(t, expected, result)
		}
	})
}
