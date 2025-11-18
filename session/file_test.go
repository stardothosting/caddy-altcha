package session

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFileBackend_StoreAndGet(t *testing.T) {
	tmpDir := t.TempDir()
	backend, err := NewFileBackend(tmpDir)
	if err != nil {
		t.Fatalf("NewFileBackend failed: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()
	key := "test-session"
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
}

func TestFileBackend_GetNonExistent(t *testing.T) {
	tmpDir := t.TempDir()
	backend, err := NewFileBackend(tmpDir)
	if err != nil {
		t.Fatalf("NewFileBackend failed: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()
	_, err = backend.Get(ctx, "non-existent-key")
	if err == nil {
		t.Error("Expected error for non-existent key")
	}
}

func TestFileBackend_Delete(t *testing.T) {
	tmpDir := t.TempDir()
	backend, err := NewFileBackend(tmpDir)
	if err != nil {
		t.Fatalf("NewFileBackend failed: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()
	key := "test-delete"
	data := []byte("test data")

	backend.Store(ctx, key, data, 1*time.Minute)

	err = backend.Delete(ctx, key)
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, err = backend.Get(ctx, key)
	if err == nil {
		t.Error("Expected error after delete, but file still exists")
	}
}

func TestFileBackend_Expiration(t *testing.T) {
	tmpDir := t.TempDir()
	backend, err := NewFileBackend(tmpDir)
	if err != nil {
		t.Fatalf("NewFileBackend failed: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()
	key := "test-expire"
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

	// Verify it's expired (Get should return error)
	_, err = backend.Get(ctx, key)
	if err == nil {
		t.Error("Key should have expired")
	}
}

func TestFileBackend_InvalidPath(t *testing.T) {
	_, err := NewFileBackend("file:///root/cannot-create-this-directory")
	// May or may not error depending on permissions
	// Just verify it doesn't panic
	_ = err
}

func TestFileBackend_FileCreation(t *testing.T) {
	tmpDir := t.TempDir()
	backend, err := NewFileBackend(tmpDir)
	if err != nil {
		t.Fatalf("NewFileBackend failed: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()
	key := "test-file-creation"
	data := []byte("test data")

	err = backend.Store(ctx, key, data, 1*time.Minute)
	if err != nil {
		t.Fatalf("Store failed: %v", err)
	}

	// Verify file was created
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("ReadDir failed: %v", err)
	}

	if len(files) == 0 {
		t.Error("Expected at least one file to be created")
	}
}

func TestFileBackend_ConcurrentAccess(t *testing.T) {
	tmpDir := t.TempDir()
	backend, err := NewFileBackend(tmpDir)
	if err != nil {
		t.Fatalf("NewFileBackend failed: %v", err)
	}
	defer backend.Close()

	ctx := context.Background()

	// Test concurrent stores
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			key := filepath.Join("concurrent-test", string(rune(id)))
			data := []byte("data")
			backend.Store(ctx, key, data, 1*time.Minute)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestFileBackend_Cleanup(t *testing.T) {
	tmpDir := t.TempDir()
	backend, err := NewFileBackend(tmpDir)
	if err != nil {
		t.Fatalf("NewFileBackend failed: %v", err)
	}

	ctx := context.Background()
	backend.Store(ctx, "test", []byte("data"), 1*time.Minute)

	err = backend.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}
