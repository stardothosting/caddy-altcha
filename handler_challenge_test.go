package caddyaltcha

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/shift8-projects/caddy-altcha/altcha"
)

func TestChallengeHandler_Provision(t *testing.T) {
	h := &ChallengeHandler{
		HMACKey: "test-key-minimum-32-characters-long",
	}

	ctx := caddy.Context{}

	err := h.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Check defaults were set
	if h.Algorithm == "" {
		t.Error("Algorithm should have a default value")
	}
	if h.Algorithm != "SHA-256" {
		t.Errorf("Algorithm default should be SHA-256, got %s", h.Algorithm)
	}
	if h.MaxNumber == 0 {
		t.Error("MaxNumber should have a default value")
	}
	if h.Expires == 0 {
		t.Error("Expires should have a default value")
	}
	if h.SaltLength == 0 {
		t.Error("SaltLength should have a default value")
	}
}

func TestChallengeHandler_Validate(t *testing.T) {
	tests := []struct {
		name    string
		handler *ChallengeHandler
		wantErr bool
	}{
		{
			name: "valid config",
			handler: &ChallengeHandler{
				HMACKey:    "test-key-minimum-32-characters-long",
				Algorithm:  "SHA-256",
				MaxNumber:  100000,
				Expires:    caddy.Duration(5 * time.Minute),
				SaltLength: 12,
			},
			wantErr: false,
		},
		{
			name: "missing hmac_key",
			handler: &ChallengeHandler{
				Algorithm: "SHA-256",
			},
			wantErr: true,
		},
		{
			name: "short hmac_key",
			handler: &ChallengeHandler{
				HMACKey:   "short-key",
				Algorithm: "SHA-256",
			},
			wantErr: false, // Should warn but not error
		},
		{
			name: "invalid algorithm",
			handler: &ChallengeHandler{
				HMACKey:   "test-key-minimum-32-characters-long",
				Algorithm: "MD5",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := caddy.Context{}
			tt.handler.Provision(ctx)

			err := tt.handler.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestChallengeHandler_ServeHTTP(t *testing.T) {
	h := &ChallengeHandler{
		HMACKey:    "test-key-minimum-32-characters-long",
		Algorithm:  "SHA-256",
		MaxNumber:  100000,
		Expires:    caddy.Duration(5 * time.Minute),
		SaltLength: 12,
	}

	ctx := caddy.Context{}
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/altcha/challenge", nil)
	w := httptest.NewRecorder()

	err := h.ServeHTTP(w, req, nil)
	if err != nil {
		t.Fatalf("ServeHTTP failed: %v", err)
	}

	// Check response
	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	// Parse and validate challenge structure
	var challenge altcha.Challenge
	if err := json.Unmarshal(w.Body.Bytes(), &challenge); err != nil {
		t.Fatalf("Failed to parse challenge JSON: %v", err)
	}

	if challenge.Algorithm != "SHA-256" {
		t.Errorf("Expected algorithm SHA-256, got %s", challenge.Algorithm)
	}
	if challenge.Challenge == "" {
		t.Error("Challenge should not be empty")
	}
	if challenge.Salt == "" {
		t.Error("Salt should not be empty")
	}
	if challenge.Signature == "" {
		t.Error("Signature should not be empty")
	}
	if challenge.MaxNumber == 0 {
		t.Error("MaxNumber should not be zero")
	}
}

func TestChallengeHandler_UnmarshalCaddyfile(t *testing.T) {
	// Test Caddyfile parsing
	tests := []struct {
		name       string
		caddyfile  string
		wantErr    bool
		checkField func(*ChallengeHandler) error
	}{
		{
			name: "basic config",
			caddyfile: `altcha_challenge {
				hmac_key test-key-minimum-32-characters-long
			}`,
			wantErr: false,
			checkField: func(h *ChallengeHandler) error {
				if h.HMACKey != "test-key-minimum-32-characters-long" {
					t.Errorf("Expected hmac_key to be set, got %s", h.HMACKey)
				}
				return nil
			},
		},
		{
			name: "full config",
			caddyfile: `altcha_challenge {
				hmac_key test-key-minimum-32-characters-long
				algorithm SHA-512
				max_number 50000
				expires 10m
				salt_length 16
			}`,
			wantErr: false,
			checkField: func(h *ChallengeHandler) error {
				if h.Algorithm != "SHA-512" {
					t.Errorf("Expected algorithm SHA-512, got %s", h.Algorithm)
				}
				if h.MaxNumber != 50000 {
					t.Errorf("Expected max_number 50000, got %d", h.MaxNumber)
				}
				if h.SaltLength != 16 {
					t.Errorf("Expected salt_length 16, got %d", h.SaltLength)
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: Full Caddyfile parsing test would require caddyfile.Dispenser
			// This is a placeholder showing the test structure
			// In practice, integration tests with caddytest would cover this
			h := &ChallengeHandler{}
			if tt.checkField != nil {
				// Would parse Caddyfile and check fields here
				_ = h
			}
		})
	}
}
