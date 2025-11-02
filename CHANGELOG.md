# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-11-02

### Major Release - Focused Architecture

This release removes built-in rate limiting to focus go-apikeys on its core responsibility: API key authentication and management.

### Breaking Changes

**REMOVED: Built-in Rate Limiting**
- Removed `EnableRateLimit` config field
- Removed `RateLimitRules` config field
- Removed `RateLimitRule` model
- Removed `RateLimiterInterface` and implementations
- Removed `ErrRateLimitExceeded` and `ErrFailedToCheckRateLimit` errors
- Removed rate limiting validation logic
- Removed rate limiting tests (1,324 lines)

**RATIONALE:**
Following the Unix philosophy of "do one thing well," go-apikeys now focuses exclusively on:
- ✅ API key authentication
- ✅ API key management (CRUD)
- ✅ Secure key generation and hashing
- ✅ Framework-agnostic middleware

Users now have full flexibility to choose their preferred rate limiting solution and compose it with go-apikeys.

### Added

**New Documentation**
- **Added**: `docs/RATE_LIMITING.md` - Comprehensive guide for integrating rate limiting
  - Recommended solution: [gorly](https://github.com/itsatony/gorly) (production-grade, tier-based)
  - Full integration examples with go-apikeys
  - Middleware composition patterns
  - Alternative rate limiter options

**Enhanced Features**
- **Added**: "Composable" as core feature in README
- **Improved**: Documentation focus on single responsibility
- **Improved**: Cleaner configuration structure

### Migration Guide (v1.x → v2.0.0)

**If you were NOT using rate limiting:**
- No changes required! Update your dependency and continue.

**If you were using rate limiting:**
1. Remove `EnableRateLimit` and `RateLimitRules` from your config
2. Choose a rate limiting library (we recommend [gorly](https://github.com/itsatony/gorly))
3. Integrate rate limiting middleware after go-apikeys middleware
4. See [docs/RATE_LIMITING.md](docs/RATE_LIMITING.md) for complete examples

Example migration:
```go
// OLD (v1.x)
config := &apikeys.Config{
    EnableRateLimit: true,
    RateLimitRules: []apikeys.RateLimitRule{...},
}

// NEW (v2.x) - Use gorly or your preferred rate limiter
import "github.com/itsatony/gorly"

gorlyLimiter, _ := gorly.NewSimple(store, 100, time.Minute)
handler := RateLimitMiddleware(gorlyLimiter)(apikeyManager.Middleware()(mux))
```

### Quality Metrics

**Testing**
- ✅ All 130+ tests pass
- ✅ Zero race conditions
- ✅ Clean build
- ✅ Zero vet issues
- ✅ Zero vulnerabilities (govulncheck)

**Code Quality**
- **Removed**: 1,324 lines of rate limiting code
- **Improved**: Focused, maintainable codebase
- **Improved**: Clear separation of concerns

## [1.0.1] - 2025-11-02

### Patch Release - Critical Bug Fixes

This patch release fixes critical data race conditions discovered through comprehensive concurrent testing.

### Fixed

#### Critical Production Bugs
- **Fixed**: Data race in `CreateAPIKey()` - now returns defensive copy instead of mutating stored pointer (apikeys.service.keys.go:122-158)
- **Fixed**: Data race in `UpdateAPIKey()` - added defensive copying before sanitization to prevent concurrent mutation (apikeys.service.keys.go:235-251)
- **Fixed**: Test code accessing empty `APIKey` field in search results (apikeys.service.keys_concurrent_test.go:738)
- **Fixed**: Data race in mock repository - added mutex protection for concurrent map access

### Added

#### Comprehensive Concurrent Testing
- **Added**: 15 concurrent test scenarios covering all service operations (790 lines)
  - Concurrent API key creation (100 goroutines)
  - Concurrent cache operations (reads, writes, invalidation, eviction)
  - Concurrent validation and authentication
  - Concurrent updates (same key and different keys)
  - Concurrent search operations
  - Concurrent delete operations with read conflicts
  - Context cancellation handling
  - Mixed workload stress testing (realistic production scenarios)
- **Added**: Deep copy helper function for thread-safe test data
- **Added**: Mutex-protected mock repository for safe concurrent testing

### Testing

#### Validation & Quality Assurance
- **Coverage**: Increased from 33.4% to 69.1% (+35.7 percentage points)
- **Stress Testing**: All tests pass 100 consecutive iterations with race detector (642s total)
- **Race Detection**: Zero race conditions detected in production code
- **Quality Gates**: All 6 gates passed
  - ✅ GATE 1: Clean build verification
  - ✅ GATE 2: Test suite with race detector
  - ✅ GATE 3: Zero vet issues
  - ✅ GATE 4: Zero security vulnerabilities (govulncheck)
  - ✅ GATE 5: Documentation compliance
  - ✅ GATE 6: Final 10x stress test

### Technical Details

#### Root Cause Analysis
The data races were caused by storing pointers in the repository and then modifying those pointers after storage. In concurrent scenarios, other goroutines could be reading the same pointer while it was being modified, causing undefined behavior.

#### Solution Approach
1. **CreateAPIKey**: Returns a defensive copy of the stored data with the plain API key set
2. **UpdateAPIKey**: Creates a deep copy of input before sanitization to prevent mutation
3. **Test Infrastructure**: Added proper synchronization primitives to test helpers

### Performance

- Thread-safe operations with no performance degradation
- Defensive copying only where necessary (API key operations)
- All concurrent operations validated under load

---

## [1.0.0] - 2025-11-02

### Major Release - Breaking Changes

This is a major release with significant architectural improvements and breaking changes. Please review the migration guide in README.md before upgrading.

### Added

#### Core Features
- **Bootstrap Service**: Automatic system admin API key creation on first run with security warnings
- **Version Management**: Integration with `go-version` for multi-dimensional version tracking
- **Handler Core Pattern**: Framework-agnostic business logic layer eliminates code duplication
- **Comprehensive Testing**: 130+ test cases with 34.5% coverage, zero race conditions
- **go-cuserr Integration**: Standardized error handling and categorization
- **Clean Architecture**: Service layer, repository pattern, and dependency injection

#### New Components
- `apikeys.service.bootstrap.go`: Bootstrap service for initial setup
- `apikeys.service.ratelimiter.stub.go`: Development/testing rate limiter stub
- `apikeys.service.ratelimiter.interface.go`: Rate limiter interface for custom implementations
- `apikeys.handlers.core.go`: Framework-agnostic handler logic (213 lines)
- `apikeys.version.go`: Version management with embedded versions.yaml
- `apikeys.repository.adapter.go`: Adapter for go-datarepository integration

#### Test Files
- `apikeys.helpers_test.go`: Key generation and hashing tests (135 lines)
- `apikeys.validation_test.go`: Input validation tests (197 lines)
- `apikeys.service.keys_test.go`: Service layer tests (417 lines)
- `apikeys.handlers.core_test.go`: Handler logic tests (356 lines)
- `models_test.go`: Model method tests (102 lines)
- `middleware_test.go`: Middleware tests for Fiber and stdlib (436 lines)
- `apikeymanager_test.go`: Manager delegation tests (233 lines)

### Changed

#### Architecture
- **Clean Architecture Refactoring**: Separated concerns into layers (HTTP → Handler → Service → Repository)
- **Service Layer Extraction**: Created `APIKeyService` with business logic
- **Repository Pattern**: Abstracted storage with `APIKeyRepository` interface
- **Handler Refactoring**: Reduced Fiber handlers from 236 to 168 lines (-29%)
- **Handler Refactoring**: Reduced stdlib handlers from 322 to 193 lines (-40%)
- **Thread Safety**: Fixed all race conditions, added proper synchronization

#### Configuration
- `Config.EnableBootstrap` (bool): Replaces `SystemAPIKey` field
- `Config.BootstrapConfig` (*BootstrapConfig): Bootstrap configuration
- `Config.Framework` (HTTPFramework): Now optional, defaults to stdlib
- Context parameter required for all CRUD methods

#### Error Handling
- All errors now use `go-cuserr` for consistent categorization
- New error types: `ErrAPIKeyNotFound`, `ErrInvalidAPIKey`, etc.
- Error checking via type comparison: `err == apikeys.ErrAPIKeyNotFound`

#### Rate Limiting
- Changed from production implementation to stub (always allows)
- Interface-based design: `RateLimiterInterface`
- Can be replaced with custom implementation

### Removed

#### Breaking Removals
- **Removed**: `Config.SystemAPIKey` field (replaced by Bootstrap service)
- **Removed**: Direct Redis client usage (replaced by go-datarepository)
- **Removed**: Production rate limiter (replaced by stub + interface)
- **Removed**: Panic-prone code paths (replaced with error returns)
- **Removed**: Code duplication across framework handlers (~300 lines eliminated)

### Fixed

#### Critical Fixes
- **Fixed**: Race conditions in concurrent request handling
- **Fixed**: Panics from nil pointer dereferences
- **Fixed**: Inconsistent error handling
- **Fixed**: Memory leaks from unclosed resources
- **Fixed**: Thread-unsafe singleton initialization

#### Security Fixes
- **Enhanced**: API key hashing with SHA3-512
- **Enhanced**: Secure random key generation with crypto/rand
- **Enhanced**: Input validation and sanitization
- **Enhanced**: Clear security warnings for bootstrap mode

### Security

#### Documented Security Considerations
- **Bootstrap Mode**: Logs API keys in clear text (documented security lapse)
- **Recovery Files**: Optional key backup with 0600 permissions
- **Rate Limiter Stub**: Not suitable for production (always allows requests)
- **System Admin Keys**: Elevated privileges require secure storage

### Deprecated

- Old method signatures without `context.Context` parameter
- Direct repository access (use manager methods instead)
- String-based error checking (use type comparison)

### Testing

#### Test Coverage
- **Overall**: 34.5% coverage
- **Middleware**: 100% (critical authentication path)
- **Handler Core**: 91.3%
- **Service Layer**: 72.8%
- **Helpers**: 61.8%
- **Validation**: 55.3%
- **Zero Race Conditions**: All tests pass with `-race` flag

### Migration Guide

See README.md for detailed migration instructions from v0.x to v1.0.0.

#### Quick Migration Checklist
- [ ] Update to Go 1.24+
- [ ] Install new dependencies (`go-cuserr`, `go-version`)
- [ ] Replace `SystemAPIKey` with `EnableBootstrap`
- [ ] Add `context.Context` to all CRUD method calls
- [ ] Update error handling to use error types
- [ ] Set `EnableRateLimit: false` or implement custom limiter
- [ ] Test all authentication flows
- [ ] Run tests with `-race` flag

### Performance

- Eliminated ~300 lines of duplicated code
- Reduced framework handler sizes by 29-40%
- Improved maintainability with clean architecture
- Thread-safe concurrent request handling

### Documentation

- **Updated**: Comprehensive README with examples for all 3 frameworks
- **Added**: Architecture documentation with clean layers diagram
- **Added**: Migration guide from v0.x
- **Added**: Security warnings and best practices
- **Added**: Test coverage statistics
- **Added**: Contributing guidelines

---

## [0.4.5] - 2024-10-16

### Changed
- Minor bug fixes and dependency updates

## [0.4.0] - 2024-03-02

### Added
- Support for multiple web frameworks (Fiber, Gorilla Mux)
- Integration with go-datarepository
- Swagger annotations for CRUD endpoints

### Changed
- Migrated from direct Redis usage to go-datarepository
- Updated configuration structure

### Deprecated
- Direct Redis client usage

---

[1.0.1]: https://github.com/vaudience/go-apikeys/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/vaudience/go-apikeys/compare/v0.4.5...v1.0.0
[0.4.5]: https://github.com/vaudience/go-apikeys/compare/v0.4.0...v0.4.5
[0.4.0]: https://github.com/vaudience/go-apikeys/releases/tag/v0.4.0
