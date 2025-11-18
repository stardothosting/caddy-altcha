package session

import (
	"context"
	"testing"
	"time"
)

// Note: These tests require a running Redis instance
// Run with: go test -tags=integration ./session/...

func TestRedisBackend_StoreAndGet(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Redis integration test in short mode")
	}

	backend, err := NewRedisBackend("redis://localhost:6379/0")
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()
	key := "test-session-" + time.Now().Format("20060102150405")
	data := []byte("test data")

	err = backend.Store(ctx, key, data, 1*time.Minute)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	retrieved, err := backend.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	if string(retrieved) != string(data) {
		t.Errorf("Data mismatch: got %s, want %s", string(retrieved), string(data))
	}

	// Cleanup
	backend.Delete(ctx, key)
}

func TestRedisBackend_GetNonExistent(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Redis integration test in short mode")
	}

	backend, err := NewRedisBackend("redis://localhost:6379/0")
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()
	_, err = backend.Get(ctx, "non-existent-key")
	if err == nil {
		t.Error("Expected error for non-existent key")
	}
}

func TestRedisBackend_Delete(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Redis integration test in short mode")
	}

	backend, err := NewRedisBackend("redis://localhost:6379/0")
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()
	key := "test-delete-" + time.Now().Format("20060102150405")
	data := []byte("test data")

	backend.Store(ctx, key, data, 1*time.Minute)

	err = backend.Delete(ctx, key)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = backend.Get(ctx, key)
	if err == nil {
		t.Error("Expected error after delete, but key still exists")
	}
}

func TestRedisBackend_Expiration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Redis integration test in short mode")
	}

	backend, err := NewRedisBackend("redis://localhost:6379/0")
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()
	key := "test-expire-" + time.Now().Format("20060102150405")
	data := []byte("test data")

	// Store with 1 second TTL
	backend.Store(ctx, key, data, 1*time.Second)

	// Verify it exists
	_, err = backend.Get(ctx, key)
	if err != nil {
		t.Fatalf("Key should exist immediately after store")
	}

	// Wait for expiration
	time.Sleep(2 * time.Second)

	// Verify it's gone
	_, err = backend.Get(ctx, key)
	if err == nil {
		t.Error("Key should have expired")
	}
}

func TestRedisBackend_InvalidURI(t *testing.T) {
	_, err := NewRedisBackend("invalid://uri")
	if err == nil {
		t.Error("Expected error for invalid URI")
	}
}

func TestRedisBackend_ConnectionPooling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Redis integration test in short mode")
	}

	backend, err := NewRedisBackend("redis://localhost:6379/0")
	if err != nil {
		t.Skipf("Redis not available: %v", err)
	}
	defer backend.Close()

	// Verify connection pool stats (if available)
	// This is a basic connectivity test
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		key := "pool-test-" + time.Now().Format("20060102150405")
		backend.Store(ctx, key, []byte("data"), 10*time.Second)
		backend.Get(ctx, key)
		backend.Delete(ctx, key)
	}
}
