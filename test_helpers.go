package apikeys

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// =============================================================================
// Note: mockRepository and mockRateLimiter are defined in their respective test files
// =============================================================================

// =============================================================================
// Mock Repository with Error Injection
// =============================================================================

// mockRepositoryWithErrors extends mockRepository with error injection capabilities
type mockRepositoryWithErrors struct {
	data map[string]*APIKeyInfo

	// Error injection flags
	createError    error
	getError       error
	updateError    error
	deleteError    error
	searchError    error
	existsError    error
	serialization  error
	deserialization error
}

func newMockRepositoryWithErrors() *mockRepositoryWithErrors {
	return &mockRepositoryWithErrors{
		data: make(map[string]*APIKeyInfo),
	}
}

func (m *mockRepositoryWithErrors) Create(ctx context.Context, apiKeyInfo *APIKeyInfo) error {
	if m.createError != nil {
		return m.createError
	}
	if apiKeyInfo.APIKeyHash == "" {
		return NewValidationError("api_key_hash", "cannot be empty")
	}
	if _, exists := m.data[apiKeyInfo.APIKeyHash]; exists {
		return NewValidationError("api_key", "already exists")
	}
	if m.serialization != nil {
		return m.serialization
	}
	m.data[apiKeyInfo.APIKeyHash] = apiKeyInfo
	return nil
}

func (m *mockRepositoryWithErrors) GetByHash(ctx context.Context, hash string) (*APIKeyInfo, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	if m.deserialization != nil {
		return nil, m.deserialization
	}
	if info, exists := m.data[hash]; exists {
		return info, nil
	}
	return nil, ErrAPIKeyNotFound
}

func (m *mockRepositoryWithErrors) Update(ctx context.Context, apiKeyInfo *APIKeyInfo) error {
	if m.updateError != nil {
		return m.updateError
	}
	if _, exists := m.data[apiKeyInfo.APIKeyHash]; !exists {
		return ErrAPIKeyNotFound
	}
	if m.serialization != nil {
		return m.serialization
	}
	m.data[apiKeyInfo.APIKeyHash] = apiKeyInfo
	return nil
}

func (m *mockRepositoryWithErrors) Delete(ctx context.Context, hash string) error {
	if m.deleteError != nil {
		return m.deleteError
	}
	if _, exists := m.data[hash]; !exists {
		return ErrAPIKeyNotFound
	}
	delete(m.data, hash)
	return nil
}

func (m *mockRepositoryWithErrors) Search(ctx context.Context, query map[string]interface{}, offset, limit int) ([]*APIKeyInfo, int, error) {
	if m.searchError != nil {
		return nil, 0, m.searchError
	}
	if m.deserialization != nil {
		return nil, 0, m.deserialization
	}

	var results []*APIKeyInfo
	for _, info := range m.data {
		results = append(results, info)
	}

	total := len(results)

	// Apply pagination
	start := offset
	end := offset + limit
	if start > len(results) {
		start = len(results)
	}
	if end > len(results) {
		end = len(results)
	}

	if start < end {
		results = results[start:end]
	} else {
		results = []*APIKeyInfo{}
	}

	return results, total, nil
}

func (m *mockRepositoryWithErrors) Exists(ctx context.Context, hash string) (bool, error) {
	if m.existsError != nil {
		return false, m.existsError
	}
	_, exists := m.data[hash]
	return exists, nil
}

// =============================================================================
// Mock Fiber Context
// =============================================================================

type mockFiberCtx struct {
	headers map[string]string
	params  map[string]string
	locals  map[string]interface{}
	body    []byte
	status  int
	sent    []byte
	path    string
	method  string
	context context.Context
}

func newMockFiberCtx() *mockFiberCtx {
	return &mockFiberCtx{
		headers: make(map[string]string),
		params:  make(map[string]string),
		locals:  make(map[string]interface{}),
		context: context.Background(),
	}
}

func (m *mockFiberCtx) Get(key string, defaultValue ...string) string {
	if val, ok := m.headers[key]; ok {
		return val
	}
	if len(defaultValue) > 0 {
		return defaultValue[0]
	}
	return ""
}

func (m *mockFiberCtx) Set(key, value string) {
	m.headers[key] = value
}

func (m *mockFiberCtx) Params(key string, defaultValue ...string) string {
	if val, ok := m.params[key]; ok {
		return val
	}
	if len(defaultValue) > 0 {
		return defaultValue[0]
	}
	return ""
}

func (m *mockFiberCtx) Status(status int) *mockFiberCtx {
	m.status = status
	return m
}

func (m *mockFiberCtx) Send(body []byte) error {
	m.sent = body
	return nil
}

func (m *mockFiberCtx) JSON(data interface{}) error {
	jsonBytes, err := json.Marshal(data)
	if err != nil {
		return err
	}
	m.sent = jsonBytes
	return nil
}

func (m *mockFiberCtx) Body() []byte {
	return m.body
}

func (m *mockFiberCtx) BodyParser(out interface{}) error {
	if m.body == nil {
		return errors.New("empty body")
	}
	return json.Unmarshal(m.body, out)
}

func (m *mockFiberCtx) UserContext() context.Context {
	return m.context
}

func (m *mockFiberCtx) SetUserContext(ctx context.Context) {
	m.context = ctx
}

func (m *mockFiberCtx) Locals(key interface{}, value ...interface{}) interface{} {
	if len(value) > 0 {
		m.locals[key.(string)] = value[0]
		return value[0]
	}
	return m.locals[key.(string)]
}

func (m *mockFiberCtx) Path() string {
	return m.path
}

func (m *mockFiberCtx) Method() string {
	return m.method
}

func (m *mockFiberCtx) Next() error {
	return nil
}

// =============================================================================
// Mock HTTP ResponseWriter
// =============================================================================

type mockResponseWriter struct {
	headers    http.Header
	body       *bytes.Buffer
	statusCode int
}

func newMockResponseWriter() *mockResponseWriter {
	return &mockResponseWriter{
		headers: make(http.Header),
		body:    new(bytes.Buffer),
	}
}

func (m *mockResponseWriter) Header() http.Header {
	return m.headers
}

func (m *mockResponseWriter) Write(b []byte) (int, error) {
	return m.body.Write(b)
}

func (m *mockResponseWriter) WriteHeader(statusCode int) {
	m.statusCode = statusCode
}


// =============================================================================
// Test Config Builders
// =============================================================================

// Note: These functions return minimal configs for testing.
// Use NewTestService() functions below for creating fully-configured test services.

// =============================================================================
// Test APIKeyInfo Builders
// =============================================================================

// NewTestAPIKeyInfo creates a minimal valid APIKeyInfo for testing
func NewTestAPIKeyInfo() *APIKeyInfo {
	return &APIKeyInfo{
		UserID: "test-user",
		OrgID:  "test-org",
		Email:  "test@example.com",
	}
}

// NewTestAPIKeyInfoWithMetadata creates an APIKeyInfo with metadata
func NewTestAPIKeyInfoWithMetadata() *APIKeyInfo {
	info := NewTestAPIKeyInfo()
	info.Metadata = map[string]any{
		"key1": "value1",
		"key2": 123,
	}
	return info
}

// NewTestAdminAPIKeyInfo creates an APIKeyInfo for system admin
func NewTestAdminAPIKeyInfo() *APIKeyInfo {
	info := NewTestAPIKeyInfo()
	info.UserID = "admin"
	info.OrgID = "system"
	info.Metadata = map[string]any{
		METADATA_KEY_SYSTEM_ADMIN: true,
	}
	return info
}

// NewTestAPIKeyInfoWithRoles creates an APIKeyInfo with roles and rights
func NewTestAPIKeyInfoWithRoles(roles, rights []string) *APIKeyInfo {
	info := NewTestAPIKeyInfo()
	info.Roles = roles
	info.Rights = rights
	return info
}

// NewTestAPIKeyInfoFull creates a fully populated APIKeyInfo
func NewTestAPIKeyInfoFull() *APIKeyInfo {
	return &APIKeyInfo{
		UserID: "full-user",
		OrgID:  "full-org",
		Email:  "full@example.com",
		Name:   "Full Test Key",
		Roles:  []string{"admin", "developer"},
		Rights: []string{"read", "write", "delete"},
		Metadata: map[string]any{
			"env":     "test",
			"purpose": "automated-testing",
		},
	}
}

// =============================================================================
// Test HTTP Request Builders
// =============================================================================

// NewTestHTTPRequest creates a test HTTP request
func NewTestHTTPRequest(method, path string, body io.Reader) *http.Request {
	req := httptest.NewRequest(method, path, body)
	req.Header.Set("Content-Type", "application/json")
	return req
}

// NewTestHTTPRequestWithAPIKey creates a test HTTP request with API key header
func NewTestHTTPRequestWithAPIKey(method, path, apiKey string, body io.Reader) *http.Request {
	req := NewTestHTTPRequest(method, path, body)
	req.Header.Set(DEFAULT_HEADER_KEY, apiKey)
	return req
}

// NewTestHTTPRequestWithContext creates a test HTTP request with context values
func NewTestHTTPRequestWithContext(method, path string, ctx context.Context) *http.Request {
	req := NewTestHTTPRequest(method, path, nil)
	return req.WithContext(ctx)
}

// =============================================================================
// Test Assertion Helpers
// =============================================================================

// AssertErrorType checks if an error matches the expected type
func AssertErrorType(t *testing.T, err error, expectedType error) {
	assert.Error(t, err)
	assert.True(t, errors.Is(err, expectedType),
		"Expected error type %v, got %v", expectedType, err)
}

// AssertHTTPStatus checks if an error maps to the expected HTTP status code
func AssertHTTPStatus(t *testing.T, err error, expectedStatus int) {
	status := ErrorToHTTPStatus(err)
	assert.Equal(t, expectedStatus, status,
		"Expected HTTP status %d, got %d for error: %v", expectedStatus, status, err)
}

// AssertValidationError checks if an error is a validation error with the expected field
func AssertValidationError(t *testing.T, err error, expectedField string) {
	assert.Error(t, err)
	AssertHTTPStatus(t, err, 400)
	assert.Contains(t, err.Error(), expectedField)
}

// AssertAPIKeyInfoEqual compares two APIKeyInfo objects (ignoring APIKey field)
func AssertAPIKeyInfoEqual(t *testing.T, expected, actual *APIKeyInfo) {
	assert.Equal(t, expected.UserID, actual.UserID)
	assert.Equal(t, expected.OrgID, actual.OrgID)
	assert.Equal(t, expected.Email, actual.Email)
	assert.Equal(t, expected.Name, actual.Name)
	assert.Equal(t, expected.APIKeyHash, actual.APIKeyHash)
	assert.Equal(t, expected.APIKeyHint, actual.APIKeyHint)
	assert.Equal(t, expected.Roles, actual.Roles)
	assert.Equal(t, expected.Rights, actual.Rights)
}

// AssertJSONResponse checks if a response body contains expected JSON structure
func AssertJSONResponse(t *testing.T, body []byte, expectedKeys ...string) {
	var response map[string]interface{}
	err := json.Unmarshal(body, &response)
	assert.NoError(t, err, "Response should be valid JSON")

	for _, key := range expectedKeys {
		assert.Contains(t, response, key, "Response should contain key: %s", key)
	}
}

// AssertErrorResponse checks if a response body contains error information
func AssertErrorResponse(t *testing.T, body []byte, expectedCode int) {
	var response ErrorResponse
	err := json.Unmarshal(body, &response)
	assert.NoError(t, err, "Error response should be valid JSON")
	assert.Equal(t, expectedCode, response.Code)
	assert.NotEmpty(t, response.Message)
}

// =============================================================================
// Test Service Builders
// =============================================================================

// Note: NewTestService functions are defined in individual test files
// that have access to mockRepository

// NewTestServiceWithErrors creates a test service with error injection capabilities
func NewTestServiceWithErrors(t *testing.T) (*APIKeyService, *mockRepositoryWithErrors) {
	repo := newMockRepositoryWithErrors()
	logger := zaptest.NewLogger(t)
	service, err := NewAPIKeyService(repo, logger, DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH, 0, 0)
	if err != nil {
		t.Fatalf("Failed to create test service with errors: %v", err)
	}
	return service, repo
}

// =============================================================================
// Test Data Generators
// =============================================================================

// GenerateTestAPIKey generates a valid test API key
func GenerateTestAPIKey(t *testing.T) string {
	key, err := GenerateAPIKey(DEFAULT_APIKEY_PREFIX, DEFAULT_APIKEY_LENGTH)
	if err != nil {
		t.Fatalf("Failed to generate test API key: %v", err)
	}
	return key
}

// GenerateTestAPIKeyHash generates a test API key and returns its hash
func GenerateTestAPIKeyHash(t *testing.T) (apiKey string, hash string) {
	apiKey = GenerateTestAPIKey(t)
	hashVal, _, err := GenerateAPIKeyHash(apiKey)
	if err != nil {
		t.Fatalf("Failed to generate test API key hash: %v", err)
	}
	return apiKey, hashVal
}

// CreateTestAPIKey creates and stores a test API key, returning the full info
func CreateTestAPIKey(t *testing.T, service *APIKeyService) *APIKeyInfo {
	info := NewTestAPIKeyInfo()
	created, err := service.CreateAPIKey(context.Background(), info)
	assert.NoError(t, err, "Failed to create test API key")
	return created
}

// CreateTestAdminAPIKey creates and stores an admin API key
func CreateTestAdminAPIKey(t *testing.T, service *APIKeyService) *APIKeyInfo {
	info := NewTestAdminAPIKeyInfo()
	created, err := service.CreateAPIKey(context.Background(), info)
	assert.NoError(t, err, "Failed to create admin API key")
	return created
}

// =============================================================================
// Test Logger Helpers
// =============================================================================

// NewTestLogger creates a test logger that outputs to testing.T
func NewTestLogger(t *testing.T) *zap.Logger {
	return zaptest.NewLogger(t)
}

// NewSilentLogger creates a no-op logger for tests that don't need output
func NewSilentLogger() *zap.Logger {
	return zap.NewNop()
}
