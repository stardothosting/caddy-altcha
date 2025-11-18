package session

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisBackend implements Redis-based session storage
type RedisBackend struct {
	client *redis.Client
}

// NewRedisBackend creates a new Redis session backend
func NewRedisBackend(uri string) (*RedisBackend, error) {
	opts, err := redis.ParseURL(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid Redis URI: %w", err)
	}

	// Configure connection pooling
	opts.MaxIdleConns = 10
	opts.PoolSize = 100
	opts.ConnMaxIdleTime = 5 * time.Minute

	client := redis.NewClient(opts)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to Redis: %w", err)
	}

	return &RedisBackend{client: client}, nil
}

// Store saves data with a TTL
func (rb *RedisBackend) Store(ctx context.Context, key string, data []byte, ttl time.Duration) error {
	return rb.client.Set(ctx, key, data, ttl).Err()
}

// Get retrieves data by key
func (rb *RedisBackend) Get(ctx context.Context, key string) ([]byte, error) {
	return rb.client.Get(ctx, key).Bytes()
}

// Delete removes data by key
func (rb *RedisBackend) Delete(ctx context.Context, key string) error {
	return rb.client.Del(ctx, key).Err()
}

// Close cleans up resources
func (rb *RedisBackend) Close() error {
	return rb.client.Close()
}
