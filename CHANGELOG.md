# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[1.0.0]: https://github.com/vaudience/go-apikeys/compare/v0.4.5...v1.0.0
[0.4.5]: https://github.com/vaudience/go-apikeys/compare/v0.4.0...v0.4.5
[0.4.0]: https://github.com/vaudience/go-apikeys/releases/tag/v0.4.0
