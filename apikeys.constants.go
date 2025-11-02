// Package apikeys provides API key authentication and management middleware for Go applications.
//
// This file contains all constants following CODE_RULES.md principle: NO MAGIC STRINGS.
// Every string literal in the codebase must be defined here as a constant.
package apikeys

const (
	// Package metadata
	PACKAGE_NAME    = "go-apikeys"
	PACKAGE_VERSION = "1.0.0"

	// Default configuration values
	DEFAULT_HEADER_KEY         = "X-API-Key"
	DEFAULT_APIKEY_PREFIX      = "gak_" // go-apikeys prefix
	DEFAULT_APIKEY_LENGTH      = 32     // Random string length (total with prefix: 36 chars)
	DEFAULT_APIKEY_HINT_LENGTH = 3      // First/last N characters for hint
	DEFAULT_RATE_LIMIT_ENABLED = false
	DEFAULT_CRUD_ENABLED       = false
	DEFAULT_BOOTSTRAP_ENABLED  = false

	// HTTP headers
	HEADER_API_KEY       = "X-API-Key"
	HEADER_AUTHORIZATION = "Authorization"
	HEADER_CONTENT_TYPE  = "Content-Type"
	HEADER_APP_VERSION   = "X-App-Version"

	// Content types
	CONTENT_TYPE_JSON = "application/json"
	CONTENT_TYPE_TEXT = "text/plain"

	// Fiber locals keys (framework-specific - must be strings for Fiber)
	// Used by Fiber's c.Locals() which requires string keys
	LOCALS_KEY_APIKEYS = "apikeys:apikey_info"

	// Metadata keys
	METADATA_KEY_SYSTEM_ADMIN = "system_admin"
	METADATA_KEY_BOOTSTRAP    = "bootstrap"
	METADATA_KEY_CREATED_AT   = "created_at"
	METADATA_KEY_UPDATED_AT   = "updated_at"
	METADATA_KEY_CREATED_BY   = "created_by"

	// Repository keys (Redis prefixes)
	REPO_KEY_PREFIX    = "apikeys"
	REPO_KEY_SEPARATOR = ":"
	REPO_KEY_APIKEY    = "key"
	REPO_KEY_RATELIMIT = "ratelimit"

	// Rate limiting
	RATE_LIMIT_KEY_PREFIX    = "apikeys:ratelimit"
	RATE_LIMIT_KEY_SEPARATOR = ":"

	// HTTP status messages
	HTTP_MSG_OK                = "OK"
	HTTP_MSG_CREATED           = "Created"
	HTTP_MSG_NO_CONTENT        = "No Content"
	HTTP_MSG_BAD_REQUEST       = "Bad Request"
	HTTP_MSG_UNAUTHORIZED      = "Unauthorized"
	HTTP_MSG_FORBIDDEN         = "Forbidden"
	HTTP_MSG_NOT_FOUND         = "Not Found"
	HTTP_MSG_CONFLICT          = "Conflict"
	HTTP_MSG_TOO_MANY_REQUESTS = "Too Many Requests"
	HTTP_MSG_INTERNAL_ERROR    = "Internal Server Error"

	// Error messages (user-facing)
	ERROR_INVALID_API_KEY                 = "invalid API key"
	ERROR_API_KEY_REQUIRED                = "API key required"
	ERROR_API_KEY_NOT_FOUND               = "API key not found"
	ERROR_FAILED_TO_RETRIEVE_API_KEY_INFO = "failed to retrieve API key information"
	ERROR_FAILED_TO_CREATE_API_KEY        = "failed to create API key"
	ERROR_FAILED_TO_UPDATE_API_KEY        = "failed to update API key"
	ERROR_FAILED_TO_DELETE_API_KEY        = "failed to delete API key"
	ERROR_FAILED_TO_CHECK_RATE_LIMIT      = "failed to check rate limit"
	ERROR_RATE_LIMIT_EXCEEDED             = "rate limit exceeded"
	ERROR_UNAUTHORIZED_ACCESS             = "unauthorized access"
	ERROR_FORBIDDEN_OPERATION             = "forbidden operation"
	ERROR_INVALID_INPUT                   = "invalid input"
	ERROR_INVALID_CONFIGURATION           = "invalid configuration"
	ERROR_REPOSITORY_REQUIRED             = "repository is required"
	ERROR_FRAMEWORK_REQUIRED              = "HTTP framework is required"
	ERROR_MISSING_USER_ID                 = "user_id is required"
	ERROR_MISSING_ORG_ID                  = "org_id is required"
	ERROR_BOOTSTRAP_ALREADY_EXISTS        = "bootstrap key already exists"
	ERROR_BOOTSTRAP_NOT_ENABLED           = "bootstrap not enabled"
	ERROR_UNAUTHORIZED_NOT_SYSTEM_ADMIN   = "Unauthorized: not a system admin"
	ERROR_INVALID_JSON                    = "Invalid JSON"
	ERROR_CREATE_APIKEY_FAILED            = "Failed to create API key"
	ERROR_SEARCH_APIKEYS_FAILED           = "Failed to search API keys"
	ERROR_MISSING_APIKEY_OR_HASH          = "Missing API key or hash"
	ERROR_GET_APIKEY_FAILED               = "Failed to retrieve API key"
	ERROR_MISSING_APIKEY_HASH             = "Missing API key hash"
	ERROR_UPDATE_APIKEY_FAILED            = "Failed to update API key"
	ERROR_DELETE_APIKEY_FAILED            = "Failed to delete API key"

	// Log level constants
	LOG_LEVEL_DEBUG = "DEBUG"
	LOG_LEVEL_INFO  = "INFO"
	LOG_LEVEL_WARN  = "WARN"
	LOG_LEVEL_ERROR = "ERROR"
	LOG_LEVEL_FATAL = "FATAL"

	// Log message templates (use with fmt.Sprintf)
	LOG_MSG_MANAGER_CREATED       = "[%s.%s] API key manager created"
	LOG_MSG_APIKEY_CREATED        = "[%s.%s] API key created for user_id=%s org_id=%s"
	LOG_MSG_APIKEY_RETRIEVED      = "[%s.%s] API key retrieved: hash=%s"
	LOG_MSG_APIKEY_UPDATED        = "[%s.%s] API key updated: hash=%s"
	LOG_MSG_APIKEY_DELETED        = "[%s.%s] API key deleted: hash=%s"
	LOG_MSG_APIKEY_VALIDATED      = "[%s.%s] API key validated: hash=%s user_id=%s"
	LOG_MSG_RATE_LIMIT_CHECKED    = "[%s.%s] Rate limit checked: identifier=%s result=%t"
	LOG_MSG_RATE_LIMIT_EXCEEDED   = "[%s.%s] Rate limit exceeded: identifier=%s limit=%d"
	LOG_MSG_BOOTSTRAP_CREATED     = "[%s.%s] Bootstrap API key created: user_id=%s"
	LOG_MSG_BOOTSTRAP_WARNING     = "BOOTSTRAP KEY CREATED - STORE SECURELY: %s"
	LOG_MSG_MIDDLEWARE_SKIP       = "[%s.%s] Skipping API key validation for route: %s"
	LOG_MSG_CONTEXT_NOT_FOUND     = "[%s.%s] API key info not found in context"
	LOG_MSG_STUB_RATE_LIMITER     = "[%s.%s] Using stub rate limiter - always allows requests"
	LOG_MSG_INVALID_JSON          = "Invalid JSON in request body"
	LOG_MSG_CREATE_APIKEY_FAILED  = "Failed to create API key"
	LOG_MSG_SEARCH_APIKEYS_FAILED = "Failed to search API keys"
	LOG_MSG_GET_APIKEY_FAILED     = "Failed to retrieve API key"
	LOG_MSG_UPDATE_APIKEY_FAILED      = "Failed to update API key"
	LOG_MSG_DELETE_APIKEY_FAILED      = "Failed to delete API key"
	LOG_MSG_UNSUPPORTED_ROUTER        = "[GO-APIKEYS.RegisterCRUDRoutes] Unsupported router type"
	LOG_MSG_CRUD_ROUTES_REGISTERED    = "[GO-APIKEYS.RegisterCRUDRoutes] CRUD routes registered"

	// Log field names (for structured logging)
	LOG_FIELD_USER_ID     = "user_id"
	LOG_FIELD_ORG_ID      = "org_id"
	LOG_FIELD_HASH        = "hash"
	LOG_FIELD_HINT        = "hint"
	LOG_FIELD_EMAIL       = "email"
	LOG_FIELD_NAME        = "name"
	LOG_FIELD_PATH        = "path"
	LOG_FIELD_METHOD      = "method"
	LOG_FIELD_STATUS_CODE = "status_code"
	LOG_FIELD_ERROR       = "error"

	// Response JSON keys
	RESPONSE_KEY_IS_SYSTEM_ADMIN = "isSystemAdmin"
	RESPONSE_KEY_ERROR           = "error"
	RESPONSE_KEY_MESSAGE         = "message"
	RESPONSE_KEY_DATA            = "data"

	// Class names for logging (service/component identification)
	CLASS_APIKEY_MANAGER    = "APIKeyManager"
	CLASS_APIKEY_SERVICE    = "APIKeyService"
	CLASS_BOOTSTRAP_SERVICE = "BootstrapService"
	CLASS_RATE_LIMITER      = "RateLimiter"
	CLASS_MIDDLEWARE        = "Middleware"
	CLASS_CRUD_HANDLER      = "CRUDHandler"
	CLASS_REPOSITORY        = "Repository"

	// Method name prefixes (for logging)
	METHOD_NEW       = "New"
	METHOD_CREATE    = "Create"
	METHOD_GET       = "Get"
	METHOD_UPDATE    = "Update"
	METHOD_DELETE    = "Delete"
	METHOD_SEARCH    = "Search"
	METHOD_VALIDATE  = "Validate"
	METHOD_ALLOW     = "Allow"
	METHOD_BOOTSTRAP = "Bootstrap"

	// API endpoint paths
	PATH_APIKEYS        = "/apikeys"
	PATH_APIKEYS_ID     = "/apikeys/{id}"
	PATH_APIKEYS_SEARCH = "/apikeys/search"
	PATH_VERSION        = "/version"
	PATH_HEALTH         = "/health"

	// Query parameters
	QUERY_PARAM_LIMIT  = "limit"
	QUERY_PARAM_OFFSET = "offset"
	QUERY_PARAM_SORT   = "sort"
	QUERY_PARAM_ORDER  = "order"
	QUERY_PARAM_SEARCH = "q"

	// Default query values
	DEFAULT_QUERY_LIMIT      = 20
	DEFAULT_QUERY_OFFSET     = 0
	DEFAULT_QUERY_SORT       = "created_at"
	DEFAULT_QUERY_ORDER_DESC = "DESC"
	DEFAULT_QUERY_ORDER_ASC  = "ASC"

	// Bootstrap configuration
	BOOTSTRAP_RECOVERY_FILE_DEFAULT     = "./.apikeys-bootstrap-recovery"
	BOOTSTRAP_RECOVERY_FILE_PERMISSIONS = 0600 // Owner read/write only

	// Validation constants
	MIN_USER_ID_LENGTH = 1
	MAX_USER_ID_LENGTH = 255
	MIN_ORG_ID_LENGTH  = 1
	MAX_ORG_ID_LENGTH  = 255
	MIN_EMAIL_LENGTH   = 3
	MAX_EMAIL_LENGTH   = 255
	MIN_NAME_LENGTH    = 1
	MAX_NAME_LENGTH    = 255
	MIN_APIKEY_LENGTH  = 10    // Minimum length for API key
	MAX_METADATA_SIZE  = 10240 // 10KB max metadata JSON size

	// Rate limiting defaults
	DEFAULT_RATE_LIMIT_WINDOW = 60  // seconds
	DEFAULT_RATE_LIMIT_MAX    = 100 // requests per window

	// Hash algorithm
	HASH_ALGORITHM = "SHA3-512"
	HASH_ENCODING  = "hex"

	// Regular expression patterns
	REGEX_EMAIL         = `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`
	REGEX_APIKEY_FORMAT = `^[a-z]{2,5}_[A-Za-z0-9_-]{10,}$` // prefix_randomstring

	// Environment variables
	ENV_LOG_LEVEL         = "APIKEYS_LOG_LEVEL"
	ENV_REDIS_URL         = "APIKEYS_REDIS_URL"
	ENV_BOOTSTRAP_ENABLED = "APIKEYS_BOOTSTRAP_ENABLED"

	// Feature flags
	FEATURE_CRUD       = "crud"
	FEATURE_RATE_LIMIT = "rate_limit"
	FEATURE_BOOTSTRAP  = "bootstrap"
	FEATURE_EVENTS     = "events"

	// Framework identifiers
	FRAMEWORK_FIBER  = "fiber"
	FRAMEWORK_MUX    = "mux"
	FRAMEWORK_STDLIB = "stdlib"

	// JSON field names (for consistency)
	JSON_FIELD_API_KEY      = "api_key"
	JSON_FIELD_API_KEY_HASH = "api_key_hash"
	JSON_FIELD_API_KEY_HINT = "api_key_hint"
	JSON_FIELD_USER_ID      = "user_id"
	JSON_FIELD_ORG_ID       = "org_id"
	JSON_FIELD_NAME         = "name"
	JSON_FIELD_EMAIL        = "email"
	JSON_FIELD_ROLES        = "roles"
	JSON_FIELD_RIGHTS       = "rights"
	JSON_FIELD_METADATA     = "metadata"
	JSON_FIELD_ERROR        = "error"
	JSON_FIELD_MESSAGE      = "message"
	JSON_FIELD_CODE         = "code"
	JSON_FIELD_DETAILS      = "details"

	// Rate limit rule targets
	RATE_LIMIT_TARGET_APIKEY = "apikey"
	RATE_LIMIT_TARGET_USER   = "user"
	RATE_LIMIT_TARGET_ORG    = "org"
	RATE_LIMIT_TARGET_IP     = "ip"

	// Operation identifiers (for tracing/logging)
	OPERATION_CREATE_APIKEY  = "create_apikey"
	OPERATION_GET_APIKEY     = "get_apikey"
	OPERATION_UPDATE_APIKEY  = "update_apikey"
	OPERATION_DELETE_APIKEY  = "delete_apikey"
	OPERATION_SEARCH_APIKEYS = "search_apikeys"
	OPERATION_VALIDATE       = "validate_apikey"
	OPERATION_RATE_LIMIT     = "rate_limit_check"
	OPERATION_BOOTSTRAP      = "bootstrap"

	// Test/development constants
	TEST_APIKEY_PREFIX  = "test_"
	TEST_USER_ID_PREFIX = "usr_test_"
	TEST_ORG_ID_PREFIX  = "org_test_"
)

// RateLimitRuleTarget represents where rate limiting is applied
type RateLimitRuleTarget string

const (
	RateLimitRuleTargetAPIKey RateLimitRuleTarget = RATE_LIMIT_TARGET_APIKEY
	RateLimitRuleTargetUserID RateLimitRuleTarget = RATE_LIMIT_TARGET_USER
	RateLimitRuleTargetOrgID  RateLimitRuleTarget = RATE_LIMIT_TARGET_ORG
	RateLimitRuleTargetIP     RateLimitRuleTarget = RATE_LIMIT_TARGET_IP
)

// contextKey is an unexported type for context keys to prevent collisions.
// Using an unexported type ensures only this package can create context keys,
// preventing other middleware from accidentally overwriting our values.
type contextKey string

// Context keys for stdlib context.Context (type-safe to prevent collisions)
var (
	contextKeyAPIKeyInfo contextKey = "apikeys:apikey_info"
)
