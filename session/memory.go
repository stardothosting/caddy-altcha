package session

import (
	"context"
	"errors"
	"sync"
	"time"
)

// MemoryBackend implements an in-memory session storage with LRU eviction
type MemoryBackend struct {
	data    map[string]*memoryEntry
	maxSize int
	mu      sync.RWMutex
}

type memoryEntry struct {
	data      []byte
	expiresAt time.Time
}

// NewMemoryBackend creates a new in-memory session backend
func NewMemoryBackend(maxSize int) *MemoryBackend {
	if maxSize <= 0 {
		maxSize = 10000
	}

	mb := &MemoryBackend{
		data:    make(map[string]*memoryEntry),
		maxSize: maxSize,
	}

	// Start cleanup goroutine
	go mb.cleanup()

	return mb
}

// Store saves data with a TTL
func (mb *MemoryBackend) Store(ctx context.Context, key string, data []byte, ttl time.Duration) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	// Evict old entries if at capacity
	if len(mb.data) >= mb.maxSize {
		mb.evictOldest()
	}

	mb.data[key] = &memoryEntry{
		data:      data,
		expiresAt: time.Now().Add(ttl),
	}

	return nil
}

// Get retrieves data by key
func (mb *MemoryBackend) Get(ctx context.Context, key string) ([]byte, error) {
	mb.mu.RLock()
	defer mb.mu.RUnlock()

	entry, exists := mb.data[key]
	if !exists {
		return nil, errors.New("session not found")
	}

	// Check expiration
	if time.Now().After(entry.expiresAt) {
		return nil, errors.New("session expired")
	}

	return entry.data, nil
}

// Delete removes data by key
func (mb *MemoryBackend) Delete(ctx context.Context, key string) error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	delete(mb.data, key)
	return nil
}

// Close cleans up resources
func (mb *MemoryBackend) Close() error {
	mb.mu.Lock()
	defer mb.mu.Unlock()

	mb.data = nil
	return nil
}

// evictOldest removes the oldest entry (must be called with lock held)
func (mb *MemoryBackend) evictOldest() {
	var oldestKey string
	var oldestTime time.Time

	for key, entry := range mb.data {
		if oldestKey == "" || entry.expiresAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.expiresAt
		}
	}

	if oldestKey != "" {
		delete(mb.data, oldestKey)
	}
}

// cleanup periodically removes expired entries
func (mb *MemoryBackend) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		mb.mu.Lock()
		now := time.Now()
		for key, entry := range mb.data {
			if now.After(entry.expiresAt) {
				delete(mb.data, key)
			}
		}
		mb.mu.Unlock()
	}
}
