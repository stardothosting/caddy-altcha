package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// FileBackend implements file-based session storage
type FileBackend struct {
	dir string
}

type fileEntry struct {
	Data      []byte    `json:"data"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewFileBackend creates a new file-based session backend
func NewFileBackend(dir string) (*FileBackend, error) {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create session directory: %w", err)
	}

	fb := &FileBackend{dir: dir}

	// Start cleanup goroutine
	go fb.cleanup()

	return fb, nil
}

// Store saves data with a TTL
func (fb *FileBackend) Store(ctx context.Context, key string, data []byte, ttl time.Duration) error {
	filename := fb.keyToFilename(key)

	// Create entry with expiration
	expiresAt := time.Now().Add(ttl)

	// Write data and expiration (simple format: expiration timestamp + newline + data)
	content := fmt.Sprintf("%d\n", expiresAt.Unix())

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create session file: %w", err)
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		return err
	}

	if _, err := f.Write(data); err != nil {
		return err
	}

	return nil
}

// Get retrieves data by key
func (fb *FileBackend) Get(ctx context.Context, key string) ([]byte, error) {
	filename := fb.keyToFilename(key)

	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.New("session not found")
		}
		return nil, err
	}

	// Parse expiration and data
	var expiresAt int64
	n, err := fmt.Sscanf(string(data), "%d\n", &expiresAt)
	if err != nil || n != 1 {
		return nil, errors.New("corrupted session file")
	}

	// Check expiration
	if time.Now().Unix() > expiresAt {
		os.Remove(filename)
		return nil, errors.New("session expired")
	}

	// Find where actual data starts (after first newline)
	dataStart := 0
	for i, b := range data {
		if b == '\n' {
			dataStart = i + 1
			break
		}
	}

	return data[dataStart:], nil
}

// Delete removes data by key
func (fb *FileBackend) Delete(ctx context.Context, key string) error {
	filename := fb.keyToFilename(key)
	err := os.Remove(filename)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// Close cleans up resources
func (fb *FileBackend) Close() error {
	return nil
}

// keyToFilename converts a key to a safe filename
func (fb *FileBackend) keyToFilename(key string) string {
	hash := sha256.Sum256([]byte(key))
	return filepath.Join(fb.dir, hex.EncodeToString(hash[:]))
}

// cleanup periodically removes expired files
func (fb *FileBackend) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		filepath.Walk(fb.dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}

			// Read and check expiration
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}

			var expiresAt int64
			n, err := fmt.Sscanf(string(data), "%d\n", &expiresAt)
			if err != nil || n != 1 {
				return nil
			}

			if time.Now().Unix() > expiresAt {
				os.Remove(path)
			}

			return nil
		})
	}
}
