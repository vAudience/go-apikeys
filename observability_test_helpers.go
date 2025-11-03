package apikeys

import (
	"context"
	"sync"
	"time"
)

// mockMetricsProvider is an in-memory metrics provider for testing
type mockMetricsProvider struct {
	mu               sync.Mutex
	authAttempts     []mockAuthAttempt
	authErrors       []mockAuthError
	operations       []mockOperation
	operationErrors  []mockOperationError
	cacheHits        int
	cacheMisses      int
	cacheEvictions   []string
	activeKeysCounts []int64
}

type mockAuthAttempt struct {
	success bool
	latency time.Duration
	labels  map[string]string
}

type mockAuthError struct {
	errorType string
	labels    map[string]string
}

type mockOperation struct {
	operation string
	latency   time.Duration
	labels    map[string]string
}

type mockOperationError struct {
	operation string
	errorType string
}

func newMockMetricsProvider() *mockMetricsProvider {
	return &mockMetricsProvider{
		authAttempts:    make([]mockAuthAttempt, 0),
		authErrors:      make([]mockAuthError, 0),
		operations:      make([]mockOperation, 0),
		operationErrors: make([]mockOperationError, 0),
		cacheEvictions:  make([]string, 0),
		activeKeysCounts: make([]int64, 0),
	}
}

func (m *mockMetricsProvider) RecordAuthAttempt(ctx context.Context, success bool, latency time.Duration, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authAttempts = append(m.authAttempts, mockAuthAttempt{
		success: success,
		latency: latency,
		labels:  copyLabels(labels),
	})
}

func (m *mockMetricsProvider) RecordAuthError(ctx context.Context, errorType string, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authErrors = append(m.authErrors, mockAuthError{
		errorType: errorType,
		labels:    copyLabels(labels),
	})
}

func (m *mockMetricsProvider) RecordOperation(ctx context.Context, operation string, latency time.Duration, labels map[string]string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.operations = append(m.operations, mockOperation{
		operation: operation,
		latency:   latency,
		labels:    copyLabels(labels),
	})
}

func (m *mockMetricsProvider) RecordOperationError(ctx context.Context, operation string, errorType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.operationErrors = append(m.operationErrors, mockOperationError{
		operation: operation,
		errorType: errorType,
	})
}

func (m *mockMetricsProvider) RecordCacheHit(ctx context.Context, key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cacheHits++
}

func (m *mockMetricsProvider) RecordCacheMiss(ctx context.Context, key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cacheMisses++
}

func (m *mockMetricsProvider) RecordCacheEviction(ctx context.Context, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cacheEvictions = append(m.cacheEvictions, reason)
}

func (m *mockMetricsProvider) RecordActiveKeys(ctx context.Context, count int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeKeysCounts = append(m.activeKeysCounts, count)
}

// Helper methods for test assertions

func (m *mockMetricsProvider) GetAuthAttemptCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.authAttempts)
}

func (m *mockMetricsProvider) GetAuthSuccessCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, attempt := range m.authAttempts {
		if attempt.success {
			count++
		}
	}
	return count
}

func (m *mockMetricsProvider) GetAuthFailureCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, attempt := range m.authAttempts {
		if !attempt.success {
			count++
		}
	}
	return count
}

func (m *mockMetricsProvider) GetOperationCount(operation string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, op := range m.operations {
		if op.operation == operation {
			count++
		}
	}
	return count
}

func (m *mockMetricsProvider) GetCacheHitCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cacheHits
}

func (m *mockMetricsProvider) GetCacheMissCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cacheMisses
}

func (m *mockMetricsProvider) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authAttempts = make([]mockAuthAttempt, 0)
	m.authErrors = make([]mockAuthError, 0)
	m.operations = make([]mockOperation, 0)
	m.operationErrors = make([]mockOperationError, 0)
	m.cacheHits = 0
	m.cacheMisses = 0
	m.cacheEvictions = make([]string, 0)
	m.activeKeysCounts = make([]int64, 0)
}

// mockAuditProvider is an in-memory audit provider for testing
type mockAuditProvider struct {
	mu              sync.Mutex
	authEvents      []*AuthAttemptEvent
	keyCreatedEvents []*KeyLifecycleEvent
	keyUpdatedEvents []*KeyLifecycleEvent
	keyDeletedEvents []*KeyLifecycleEvent
	keyAccessEvents  []*KeyAccessEvent
	securityEvents   []*SecurityEvent
}

func newMockAuditProvider() *mockAuditProvider {
	return &mockAuditProvider{
		authEvents:       make([]*AuthAttemptEvent, 0),
		keyCreatedEvents: make([]*KeyLifecycleEvent, 0),
		keyUpdatedEvents: make([]*KeyLifecycleEvent, 0),
		keyDeletedEvents: make([]*KeyLifecycleEvent, 0),
		keyAccessEvents:  make([]*KeyAccessEvent, 0),
		securityEvents:   make([]*SecurityEvent, 0),
	}
}

func (m *mockAuditProvider) LogAuthAttempt(ctx context.Context, event *AuthAttemptEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authEvents = append(m.authEvents, event)
	return nil
}

func (m *mockAuditProvider) LogKeyCreated(ctx context.Context, event *KeyLifecycleEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keyCreatedEvents = append(m.keyCreatedEvents, event)
	return nil
}

func (m *mockAuditProvider) LogKeyUpdated(ctx context.Context, event *KeyLifecycleEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keyUpdatedEvents = append(m.keyUpdatedEvents, event)
	return nil
}

func (m *mockAuditProvider) LogKeyDeleted(ctx context.Context, event *KeyLifecycleEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keyDeletedEvents = append(m.keyDeletedEvents, event)
	return nil
}

func (m *mockAuditProvider) LogKeyAccessed(ctx context.Context, event *KeyAccessEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keyAccessEvents = append(m.keyAccessEvents, event)
	return nil
}

func (m *mockAuditProvider) LogSecurityEvent(ctx context.Context, event *SecurityEvent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.securityEvents = append(m.securityEvents, event)
	return nil
}

// Helper methods for test assertions

func (m *mockAuditProvider) GetAuthEventCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.authEvents)
}

func (m *mockAuditProvider) GetAuthSuccessCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, event := range m.authEvents {
		if event.Outcome == OutcomeSuccess {
			count++
		}
	}
	return count
}

func (m *mockAuditProvider) GetAuthFailureCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	count := 0
	for _, event := range m.authEvents {
		if event.Outcome == OutcomeFailure {
			count++
		}
	}
	return count
}

func (m *mockAuditProvider) GetKeyCreatedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.keyCreatedEvents)
}

func (m *mockAuditProvider) GetKeyUpdatedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.keyUpdatedEvents)
}

func (m *mockAuditProvider) GetKeyDeletedCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.keyDeletedEvents)
}

func (m *mockAuditProvider) GetSecurityEventCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.securityEvents)
}

func (m *mockAuditProvider) GetLastAuthEvent() *AuthAttemptEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.authEvents) == 0 {
		return nil
	}
	return m.authEvents[len(m.authEvents)-1]
}

func (m *mockAuditProvider) GetLastKeyCreatedEvent() *KeyLifecycleEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.keyCreatedEvents) == 0 {
		return nil
	}
	return m.keyCreatedEvents[len(m.keyCreatedEvents)-1]
}

func (m *mockAuditProvider) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authEvents = make([]*AuthAttemptEvent, 0)
	m.keyCreatedEvents = make([]*KeyLifecycleEvent, 0)
	m.keyUpdatedEvents = make([]*KeyLifecycleEvent, 0)
	m.keyDeletedEvents = make([]*KeyLifecycleEvent, 0)
	m.keyAccessEvents = make([]*KeyAccessEvent, 0)
	m.securityEvents = make([]*SecurityEvent, 0)
}

// Helper functions

func copyLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	copy := make(map[string]string, len(labels))
	for k, v := range labels {
		copy[k] = v
	}
	return copy
}
