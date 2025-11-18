package session

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Backend defines the interface for session storage
type Backend interface {
	// Store saves data with a TTL
	Store(ctx context.Context, key string, data []byte, ttl time.Duration) error

	// Get retrieves data by key
	Get(ctx context.Context, key string) ([]byte, error)

	// Delete removes data by key
	Delete(ctx context.Context, key string) error

	// Close cleans up resources
	Close() error
}

// NewBackend creates a session backend from a URI
// Supported formats:
//   - memory://
//   - redis://host:port/db
//   - file:///path/to/dir
func NewBackend(uri string) (Backend, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid session backend URI: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)

	switch scheme {
	case "memory":
		return NewMemoryBackend(10000), nil // Default max 10k entries

	case "redis":
		return NewRedisBackend(uri)

	case "file":
		return NewFileBackend(u.Path)

	default:
		return nil, fmt.Errorf("unsupported session backend: %s", scheme)
	}
}
