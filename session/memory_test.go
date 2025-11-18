package session

import (
	"context"
	"testing"
	"time"
)

func TestMemoryBackend_StoreAndGet(t *testing.T) {
	backend := NewMemoryBackend(100)
	ctx := context.Background()

	key := "test-key"
	data := []byte("test-data")
	ttl := 1 * time.Minute

	// Store data
	err := backend.Store(ctx, key, data, ttl)
	if err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	// Retrieve data
	retrieved, err := backend.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}

	if string(retrieved) != string(data) {
		t.Errorf("Get() = %s, want %s", retrieved, data)
	}
}

func TestMemoryBackend_GetNonExistent(t *testing.T) {
	backend := NewMemoryBackend(100)
	ctx := context.Background()

	_, err := backend.Get(ctx, "non-existent")
	if err == nil {
		t.Error("Get() should return error for non-existent key")
	}
}

func TestMemoryBackend_Delete(t *testing.T) {
	backend := NewMemoryBackend(100)
	ctx := context.Background()

	key := "test-key"
	data := []byte("test-data")

	// Store and delete
	backend.Store(ctx, key, data, 1*time.Minute)
	err := backend.Delete(ctx, key)
	if err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Verify it's gone
	_, err = backend.Get(ctx, key)
	if err == nil {
		t.Error("Get() should return error after Delete()")
	}
}

func TestMemoryBackend_Expiration(t *testing.T) {
	backend := NewMemoryBackend(100)
	ctx := context.Background()

	key := "test-key"
	data := []byte("test-data")
	ttl := 100 * time.Millisecond

	// Store with short TTL
	backend.Store(ctx, key, data, ttl)

	// Should exist immediately
	_, err := backend.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get() error = %v (should exist)", err)
	}

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should be expired
	_, err = backend.Get(ctx, key)
	if err == nil {
		t.Error("Get() should return error for expired key")
	}
}

func TestMemoryBackend_MaxSize(t *testing.T) {
	maxSize := 10
	backend := NewMemoryBackend(maxSize)
	ctx := context.Background()

	// Fill beyond capacity
	for i := 0; i < maxSize+5; i++ {
		key := string(rune('a' + i))
		backend.Store(ctx, key, []byte("data"), 1*time.Minute)
	}

	// Count entries
	backend.mu.RLock()
	count := len(backend.data)
	backend.mu.RUnlock()

	if count > maxSize {
		t.Errorf("Backend has %d entries, max is %d", count, maxSize)
	}
}

func TestMemoryBackend_Close(t *testing.T) {
	backend := NewMemoryBackend(100)

	err := backend.Close()
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	// Data should be nil after close
	backend.mu.RLock()
	data := backend.data
	backend.mu.RUnlock()

	if data != nil {
		t.Error("data should be nil after Close()")
	}
}

func BenchmarkMemoryBackend_Store(b *testing.B) {
	backend := NewMemoryBackend(10000)
	ctx := context.Background()
	data := []byte("test-data")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := string(rune(i))
		backend.Store(ctx, key, data, 1*time.Minute)
	}
}

func BenchmarkMemoryBackend_Get(b *testing.B) {
	backend := NewMemoryBackend(10000)
	ctx := context.Background()

	// Pre-populate
	for i := 0; i < 1000; i++ {
		key := string(rune(i))
		backend.Store(ctx, key, []byte("data"), 1*time.Minute)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := string(rune(i % 1000))
		backend.Get(ctx, key)
	}
}
