package caddyaltcha

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/stardothosting/caddy-altcha/altcha"
)

// ChallengeHandler generates ALTCHA challenges
type ChallengeHandler struct {
	// HMACKey is the secret key for HMAC signing
	HMACKey string `json:"hmac_key,omitempty"`

	// Algorithm is the hashing algorithm (SHA-256, SHA-384, SHA-512)
	Algorithm string `json:"algorithm,omitempty"`

	// MaxNumber is the maximum random number in the challenge
	MaxNumber int `json:"max_number,omitempty"`

	// Expires is how long the challenge is valid
	Expires caddy.Duration `json:"expires,omitempty"`

	// SaltLength is the length of the random salt
	SaltLength int `json:"salt_length,omitempty"`

	// CodeChallenge enables visual code challenges (obfuscation)
	CodeChallenge bool `json:"code_challenge,omitempty"`

	// CodeLength is the length of the visual code (default: 6)
	CodeLength int `json:"code_length,omitempty"`

	// RateLimitRequests is max requests per window (0 = disabled)
	RateLimitRequests int `json:"rate_limit_requests,omitempty"`

	// RateLimitWindow is the time window for rate limiting
	RateLimitWindow caddy.Duration `json:"rate_limit_window,omitempty"`

	log         *zap.Logger
	rateLimiter *rateLimiter
}

// rateLimiter implements a simple per-IP rate limiter
type rateLimiter struct {
	requests map[string]*ipRateLimit
	mu       sync.RWMutex
	max      int
	window   time.Duration
}

type ipRateLimit struct {
	count     int
	resetTime time.Time
}

// CaddyModule returns the Caddy module information
func (ChallengeHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.altcha_challenge",
		New: func() caddy.Module { return new(ChallengeHandler) },
	}
}

// Provision sets up the challenge handler
func (h *ChallengeHandler) Provision(ctx caddy.Context) error {
	h.log = ctx.Logger(h)

	// Set defaults
	if h.Algorithm == "" {
		h.Algorithm = "SHA-256"
	}
	if h.MaxNumber == 0 {
		h.MaxNumber = 100000
	}
	if h.Expires == 0 {
		h.Expires = caddy.Duration(5 * time.Minute)
	}
	if h.SaltLength == 0 {
		h.SaltLength = 12
	}
	if h.CodeLength == 0 {
		h.CodeLength = 6
	}

	// Initialize rate limiter if configured
	if h.RateLimitRequests > 0 {
		if h.RateLimitWindow == 0 {
			h.RateLimitWindow = caddy.Duration(1 * time.Minute)
		}
		h.rateLimiter = newRateLimiter(h.RateLimitRequests, time.Duration(h.RateLimitWindow))
		h.log.Info("rate limiting enabled",
			zap.Int("max_requests", h.RateLimitRequests),
			zap.Duration("window", time.Duration(h.RateLimitWindow)))
	}

	h.log.Info("provisioning ALTCHA challenge handler",
		zap.String("algorithm", h.Algorithm),
		zap.Int("max_number", h.MaxNumber),
		zap.Duration("expires", time.Duration(h.Expires)),
	)

	return nil
}

// Validate ensures the configuration is valid
func (h *ChallengeHandler) Validate() error {
	if h.HMACKey == "" {
		return fmt.Errorf("hmac_key is required")
	}

	if len(h.HMACKey) < 32 {
		h.log.Warn("HMAC key shorter than recommended 32 bytes",
			zap.Int("length", len(h.HMACKey)))
	}

	validAlgorithms := map[string]bool{
		"SHA-256": true,
		"SHA-384": true,
		"SHA-512": true,
	}
	if !validAlgorithms[h.Algorithm] {
		return fmt.Errorf("invalid algorithm: %s (must be SHA-256, SHA-384, or SHA-512)", h.Algorithm)
	}

	if h.MaxNumber < 1000 {
		return fmt.Errorf("max_number too small (minimum 1000)")
	}

	if time.Duration(h.Expires) < time.Minute {
		return fmt.Errorf("expires must be at least 1 minute")
	}

	return nil
}

// ServeHTTP generates and returns a challenge
func (h *ChallengeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		return caddyhttp.Error(http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}

	// Check rate limit if enabled
	if h.rateLimiter != nil {
		clientIP := r.RemoteAddr
		if !h.rateLimiter.allow(clientIP) {
			h.log.Warn("rate limit exceeded", zap.String("client_ip", clientIP))
			return caddyhttp.Error(http.StatusTooManyRequests, fmt.Errorf("rate limit exceeded"))
		}
	}

	// Create challenge
	challenge, err := altcha.CreateChallenge(altcha.ChallengeOptions{
		Algorithm:  h.Algorithm,
		MaxNumber:  h.MaxNumber,
		SaltLength: h.SaltLength,
		HMACKey:    h.HMACKey,
		Expires:    time.Now().Add(time.Duration(h.Expires)),
	})

	if err != nil {
		h.log.Error("failed to create challenge", zap.Error(err))
		return caddyhttp.Error(http.StatusInternalServerError, fmt.Errorf("failed to create challenge"))
	}

	// Add code challenge if enabled
	if h.CodeChallenge {
		codeChallenge, _, err := altcha.GenerateCodeChallenge(h.CodeLength)
		if err != nil {
			h.log.Error("failed to generate code challenge", zap.Error(err))
			// Continue without code challenge rather than failing
		} else {
			challenge.CodeChallenge = codeChallenge
			h.log.Debug("generated code challenge", zap.Int("length", h.CodeLength))
		}
	}

	h.log.Debug("generated challenge",
		zap.String("algorithm", challenge.Algorithm),
		zap.String("challenge", challenge.Challenge),
		zap.Bool("has_code_challenge", challenge.CodeChallenge != nil),
	)

	// Return as JSON
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	return json.NewEncoder(w).Encode(challenge)
}

// UnmarshalCaddyfile sets up the handler from Caddyfile
func (h *ChallengeHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "hmac_key":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.HMACKey = d.Val()

			case "algorithm":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.Algorithm = d.Val()

			case "max_number":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var maxNum int
				if _, err := fmt.Sscanf(d.Val(), "%d", &maxNum); err != nil {
					return d.Errf("invalid max_number: %v", err)
				}
				h.MaxNumber = maxNum

			case "expires":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid expires duration: %v", err)
				}
				h.Expires = caddy.Duration(dur)

			case "salt_length":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var saltLen int
				if _, err := fmt.Sscanf(d.Val(), "%d", &saltLen); err != nil {
					return d.Errf("invalid salt_length: %v", err)
				}
				h.SaltLength = saltLen

			case "code_challenge":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var enabled bool
				if _, err := fmt.Sscanf(d.Val(), "%t", &enabled); err != nil {
					return d.Errf("invalid code_challenge (use true/false): %v", err)
				}
				h.CodeChallenge = enabled

			case "code_length":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var codeLen int
				if _, err := fmt.Sscanf(d.Val(), "%d", &codeLen); err != nil {
					return d.Errf("invalid code_length: %v", err)
				}
				h.CodeLength = codeLen

			case "rate_limit_requests":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var rateLimit int
				if _, err := fmt.Sscanf(d.Val(), "%d", &rateLimit); err != nil {
					return d.Errf("invalid rate_limit_requests: %v", err)
				}
				h.RateLimitRequests = rateLimit

			case "rate_limit_window":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid rate_limit_window: %v", err)
				}
				h.RateLimitWindow = caddy.Duration(dur)

			default:
				return d.Errf("unknown subdirective: %s", d.Val())
			}
		}
	}

	return nil
}

// newRateLimiter creates a new rate limiter
func newRateLimiter(max int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		requests: make(map[string]*ipRateLimit),
		max:      max,
		window:   window,
	}
	
	// Start cleanup goroutine
	go rl.cleanup()
	
	return rl
}

// allow checks if a request from the given IP is allowed
func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	
	if limit, exists := rl.requests[ip]; exists {
		if now.After(limit.resetTime) {
			// Window expired, reset counter
			limit.count = 1
			limit.resetTime = now.Add(rl.window)
			return true
		}
		
		if limit.count >= rl.max {
			// Rate limit exceeded
			return false
		}
		
		// Increment counter
		limit.count++
		return true
	}
	
	// First request from this IP
	rl.requests[ip] = &ipRateLimit{
		count:     1,
		resetTime: now.Add(rl.window),
	}
	return true
}

// cleanup periodically removes expired entries
func (rl *rateLimiter) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, limit := range rl.requests {
			if now.After(limit.resetTime) {
				delete(rl.requests, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// Interface guards
var (
	_ caddy.Provisioner           = (*ChallengeHandler)(nil)
	_ caddy.Validator             = (*ChallengeHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*ChallengeHandler)(nil)
	_ caddyfile.Unmarshaler       = (*ChallengeHandler)(nil)
)
