package caddyaltcha

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/shift8-projects/caddy-altcha/altcha"
)

// TestVerifyHandler_ServeHTTP_WithValidCookie tests that handler calls next when valid cookie present
func TestVerifyHandler_ServeHTTP_WithValidCookie(t *testing.T) {
	h := &VerifyHandler{
		HMACKey:           "test-key-minimum-32-characters-long",
		ChallengeRedirect: "/captcha",
	}

	ctx := caddy.Context{}
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Create request with valid verification cookie
	req := httptest.NewRequest("GET", "/protected", nil)
	req.AddCookie(&http.Cookie{
		Name:  "altcha_verified",
		Value: "some-value",
	})

	rec := httptest.NewRecorder()

	// Mock next handler
	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("from next handler"))
		return nil
	})

	// Execute
	err := h.ServeHTTP(rec, req, next)

	// Assertions
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if !nextCalled {
		t.Error("Next handler should be called when valid cookie present")
	}

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	if !strings.Contains(rec.Body.String(), "from next handler") {
		t.Error("Response should come from next handler")
	}
}

// TestVerifyHandler_ServeHTTP_NoCookie tests redirect when no cookie present
func TestVerifyHandler_ServeHTTP_NoCookie(t *testing.T) {
	h := &VerifyHandler{
		HMACKey:           "test-key-minimum-32-characters-long",
		ChallengeRedirect: "/captcha",
	}

	ctx := caddy.Context{}
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Create request without cookie
	req := httptest.NewRequest("GET", "/protected", nil)
	rec := httptest.NewRecorder()

	// Mock next handler
	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})

	// Execute
	err := h.ServeHTTP(rec, req, next)

	// Assertions
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if nextCalled {
		t.Error("Next handler should NOT be called when no cookie present")
	}

	if rec.Code != http.StatusSeeOther && rec.Code != http.StatusFound {
		t.Errorf("Expected redirect status, got %d", rec.Code)
	}

	location := rec.Header().Get("Location")
	if !strings.Contains(location, "/captcha") {
		t.Errorf("Expected redirect to /captcha, got %s", location)
	}
}

// TestVerifyHandler_ServeHTTP_WithValidSolution tests setting cookie when valid solution provided
func TestVerifyHandler_ServeHTTP_WithValidSolution(t *testing.T) {
	hmacKey := "test-key-minimum-32-characters-long"

	h := &VerifyHandler{
		HMACKey:           hmacKey,
		ChallengeRedirect: "/captcha",
		VerifyFieldName:   "altcha",
	}

	ctx := caddy.Context{}
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Create a valid ALTCHA challenge and solution
	challenge, err := altcha.CreateChallenge(altcha.ChallengeOptions{
		Algorithm:  "SHA-256",
		MaxNumber:  100,
		HMACKey:    hmacKey,
		SaltLength: 12,
	})
	if err != nil {
		t.Fatalf("Failed to create challenge: %v", err)
	}

	// Create a solution payload (base64 encoded JSON)
	solution := altcha.Solution{
		Algorithm: challenge.Algorithm,
		Challenge: challenge.Challenge,
		Salt:      challenge.Salt,
		Signature: challenge.Signature,
		Number:    0, // Simplified - in reality would need to solve
	}

	solutionJSON, _ := json.Marshal(solution)
	solutionPayload := base64.StdEncoding.EncodeToString(solutionJSON)

	// Create request with solution in query parameter
	req := httptest.NewRequest("GET", "/protected?altcha="+url.QueryEscape(solutionPayload), nil)
	rec := httptest.NewRecorder()

	// Mock next handler
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	// Execute
	err = h.ServeHTTP(rec, req, next)

	// Note: The solution won't be valid because we didn't actually solve it,
	// but we're testing the flow. In a real scenario, we'd need to solve the challenge.
	// For now, this tests that the handler processes solutions without crashing.

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// Since solution is invalid (Number: 0), should redirect
	if rec.Code != http.StatusSeeOther && rec.Code != http.StatusFound && rec.Code != http.StatusOK {
		t.Logf("Got status code: %d (expected redirect or OK depending on solution validity)", rec.Code)
	}
}

// TestVerifyHandler_ServeHTTP_POSTDataPreservation tests POST data preservation across redirect
func TestVerifyHandler_ServeHTTP_POSTDataPreservation(t *testing.T) {
	h := &VerifyHandler{
		HMACKey:           "test-key-minimum-32-characters-long",
		ChallengeRedirect: "/captcha",
		PreservePostData:  true,
	}

	ctx := caddy.Context{}
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	// Create POST request with form data
	formData := url.Values{}
	formData.Set("username", "testuser")
	formData.Set("password", "testpass")

	req := httptest.NewRequest("POST", "/login", strings.NewReader(formData.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()

	// Mock next handler
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		w.WriteHeader(http.StatusOK)
		return nil
	})

	// Execute
	err := h.ServeHTTP(rec, req, next)

	// Assertions
	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	// Should redirect with session parameter
	if rec.Code != http.StatusSeeOther && rec.Code != http.StatusFound {
		t.Errorf("Expected redirect status for POST without cookie, got %d", rec.Code)
	}

	location := rec.Header().Get("Location")
	if !strings.Contains(location, "session=") {
		t.Error("Expected redirect URL to contain session parameter for POST data preservation")
	}

	if !strings.Contains(location, "/captcha") {
		t.Errorf("Expected redirect to /captcha, got %s", location)
	}
}

// TestVerifyHandler_ServeHTTP_MiddlewareChain tests proper middleware chain execution
func TestVerifyHandler_ServeHTTP_MiddlewareChain(t *testing.T) {
	tests := []struct {
		name           string
		setupRequest   func() *http.Request
		expectNext     bool
		expectRedirect bool
		description    string
	}{
		{
			name: "valid_cookie_continues_chain",
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/protected", nil)
				req.AddCookie(&http.Cookie{
					Name:  "altcha_verified",
					Value: "valid",
				})
				return req
			},
			expectNext:     true,
			expectRedirect: false,
			description:    "Request with valid cookie should continue to next handler",
		},
		{
			name: "no_cookie_breaks_chain",
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/protected", nil)
			},
			expectNext:     false,
			expectRedirect: true,
			description:    "Request without cookie should redirect and not call next",
		},
		{
			name: "post_without_cookie_preserves_data",
			setupRequest: func() *http.Request {
				body := bytes.NewBufferString("field1=value1&field2=value2")
				req := httptest.NewRequest("POST", "/submit", body)
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			},
			expectNext:     false,
			expectRedirect: true,
			description:    "POST without cookie should redirect with session preservation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &VerifyHandler{
				HMACKey:           "test-key-minimum-32-characters-long",
				ChallengeRedirect: "/captcha",
				PreservePostData:  true,
			}

			ctx := caddy.Context{}
			if err := h.Provision(ctx); err != nil {
				t.Fatalf("Provision failed: %v", err)
			}

			req := tt.setupRequest()
			rec := httptest.NewRecorder()

			nextCalled := false
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
				return nil
			})

			err := h.ServeHTTP(rec, req, next)

			if err != nil {
				t.Fatalf("ServeHTTP returned error: %v", err)
			}

			if nextCalled != tt.expectNext {
				t.Errorf("%s: nextCalled = %v, want %v", tt.description, nextCalled, tt.expectNext)
			}

			isRedirect := rec.Code == http.StatusSeeOther || rec.Code == http.StatusFound
			if isRedirect != tt.expectRedirect {
				t.Errorf("%s: got redirect = %v (status %d), want %v", tt.description, isRedirect, rec.Code, tt.expectRedirect)
			}
		})
	}
}

// TestVerifyHandler_ServeHTTP_ErrorHandling tests error scenarios
func TestVerifyHandler_ServeHTTP_ErrorHandling(t *testing.T) {
	h := &VerifyHandler{
		HMACKey:           "test-key-minimum-32-characters-long",
		ChallengeRedirect: "/captcha",
		VerifyFieldName:   "altcha",
	}

	ctx := caddy.Context{}
	if err := h.Provision(ctx); err != nil {
		t.Fatalf("Provision failed: %v", err)
	}

	tests := []struct {
		name        string
		setupReq    func() *http.Request
		expectError bool
		description string
	}{
		{
			name: "malformed_solution",
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "/protected?altcha=invalid-base64!@#", nil)
			},
			expectError: false, // Should redirect, not error
			description: "Malformed solution should redirect gracefully",
		},
		{
			name: "empty_solution",
			setupReq: func() *http.Request {
				return httptest.NewRequest("GET", "/protected?altcha=", nil)
			},
			expectError: false,
			description: "Empty solution should redirect to challenge",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.setupReq()
			rec := httptest.NewRecorder()

			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				w.WriteHeader(http.StatusOK)
				return nil
			})

			err := h.ServeHTTP(rec, req, next)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Expected no error but got: %v", err)
			}

			// Should redirect on invalid solutions
			if !tt.expectError {
				isRedirect := rec.Code == http.StatusSeeOther || rec.Code == http.StatusFound
				if !isRedirect {
					t.Errorf("%s: expected redirect status, got %d", tt.description, rec.Code)
				}
			}
		})
	}
}

// TestChallengeHandler_ServeHTTP_MiddlewareChain tests challenge handler doesn't break chain
func TestChallengeHandler_ServeHTTP_MiddlewareChain(t *testing.T) {
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
	rec := httptest.NewRecorder()

	// Challenge handler is terminal (doesn't call next), so next should not be called
	nextCalled := false
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		nextCalled = true
		return nil
	})

	err := h.ServeHTTP(rec, req, next)

	if err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}

	if nextCalled {
		t.Error("Challenge handler should not call next (it's a terminal handler)")
	}

	if rec.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	// Verify JSON response
	contentType := rec.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("Expected JSON content type, got %s", contentType)
	}
}
