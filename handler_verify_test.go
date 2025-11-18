package caddyaltcha

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func TestVerifyHandler_Provision(t *testing.T) {
	h := &VerifyHandler{
		HMACKey: "test-key-minimum-32-characters-long",
	}

	// Create a proper Caddy context
	ctx := caddy.Context{}

	err := h.Provision(ctx)
	if err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Check defaults were set
	if h.SessionTTL == 0 {
		t.Error("SessionTTL should have a default value")
	}
	if h.VerifyFieldName == "" {
		t.Error("VerifyFieldName should have a default value")
	}
	if h.sessionBackend == nil {
		t.Error("sessionBackend should be initialized")
	}
}

func TestVerifyHandler_Validate(t *testing.T) {
	tests := []struct {
		name    string
		handler *VerifyHandler
		wantErr bool
	}{
		{
			name: "valid config",
			handler: &VerifyHandler{
				HMACKey:    "test-key-minimum-32-characters-long",
				SessionTTL: caddy.Duration(5 * time.Minute),
			},
			wantErr: false,
		},
		{
			name: "missing hmac_key",
			handler: &VerifyHandler{
				SessionTTL: caddy.Duration(5 * time.Minute),
			},
			wantErr: true,
		},
		{
			name: "session_ttl too short",
			handler: &VerifyHandler{
				HMACKey:    "test-key-minimum-32-characters-long",
				SessionTTL: caddy.Duration(30 * time.Second),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Provision first
			ctx := caddy.Context{}
			tt.handler.Provision(ctx)

			err := tt.handler.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyHandler_HasValidVerificationCookie(t *testing.T) {
	h := &VerifyHandler{
		HMACKey: "test-key-minimum-32-characters-long",
	}

	ctx := caddy.Context{}
	h.Provision(ctx)

	tests := []struct {
		name       string
		setCookie  bool
		cookieName string
		want       bool
	}{
		{
			name:       "valid cookie",
			setCookie:  true,
			cookieName: "altcha_verified",
			want:       true,
		},
		{
			name:      "no cookie",
			setCookie: false,
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)

			if tt.setCookie {
				req.AddCookie(&http.Cookie{
					Name:  tt.cookieName,
					Value: "test-value",
				})
			}

			got := h.hasValidVerificationCookie(req)
			if got != tt.want {
				t.Errorf("hasValidVerificationCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerifyHandler_ExtractSolution(t *testing.T) {
	h := &VerifyHandler{
		VerifyFieldName: "altcha",
	}

	tests := []struct {
		name     string
		setupReq func() *http.Request
		want     string
	}{
		{
			name: "from query parameter",
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "/test?altcha=solution123", nil)
			},
			want: "solution123",
		},
		{
			name: "from header",
			setupReq: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", nil)
				req.Header.Set("X-Altcha-Solution", "solution456")
				return req
			},
			want: "solution456",
		},
		{
			name: "no solution",
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "/test", nil)
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			got := h.extractSolution(req)
			if got != tt.want {
				t.Errorf("extractSolution() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGenerateSessionID(t *testing.T) {
	// Test that we can generate session IDs
	id1, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID() error = %v", err)
	}

	if len(id1) == 0 {
		t.Error("GenerateSessionID() returned empty string")
	}

	// Generate another and ensure they're different
	id2, err := GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID() error = %v", err)
	}

	if id1 == id2 {
		t.Error("GenerateSessionID() returned duplicate IDs")
	}
}

func TestGenerateCookieValue(t *testing.T) {
	// Test that we can generate cookie values
	val1, err := GenerateCookieValue()
	if err != nil {
		t.Fatalf("GenerateCookieValue() error = %v", err)
	}

	if len(val1) == 0 {
		t.Error("GenerateCookieValue() returned empty string")
	}

	// Generate another and ensure they're different
	val2, err := GenerateCookieValue()
	if err != nil {
		t.Fatalf("GenerateCookieValue() error = %v", err)
	}

	if val1 == val2 {
		t.Error("GenerateCookieValue() returned duplicate values")
	}
}

// Mock next handler for testing
type mockHandler struct {
	called bool
}

func (m *mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	m.called = true
	w.WriteHeader(http.StatusOK)
	return nil
}

var _ caddyhttp.Handler = (*mockHandler)(nil)
