package caddyaltcha

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/stardothosting/caddy-altcha/altcha"
	"github.com/stardothosting/caddy-altcha/session"
)

// VerifyHandler verifies ALTCHA solutions
type VerifyHandler struct {
	// HMACKey is the secret key for HMAC verification
	HMACKey string `json:"hmac_key,omitempty"`

	// SessionBackend is the URI for session storage
	SessionBackendURI string `json:"session_backend,omitempty"`

	// SessionTTL is how long sessions are valid
	SessionTTL caddy.Duration `json:"session_ttl,omitempty"`

	// VerifiedCookie configuration
	VerifiedCookieName     string `json:"verified_cookie_name,omitempty"`
	VerifiedCookieTTL      int    `json:"verified_cookie_ttl,omitempty"`
	VerifiedCookieSecure   bool   `json:"verified_cookie_secure,omitempty"`
	VerifiedCookieHTTPOnly bool   `json:"verified_cookie_http_only,omitempty"`
	VerifiedCookieSameSite string `json:"verified_cookie_same_site,omitempty"`
	VerifiedCookiePath     string `json:"verified_cookie_path,omitempty"`
	VerifiedCookieDomain   string `json:"verified_cookie_domain,omitempty"`

	// ChallengeRedirect is where to redirect for challenge
	ChallengeRedirect string `json:"challenge_redirect,omitempty"`

	// PreservePostData preserves POST data across redirects
	PreservePostData bool `json:"preserve_post_data,omitempty"`

	// CorazaEnvVar is the environment variable set by Coraza WAF
	CorazaEnvVar string `json:"coraza_env_var,omitempty"`

	// VerifyFieldName is the form field containing the ALTCHA solution
	VerifyFieldName string `json:"verify_field_name,omitempty"`

	// ChallengeUIPath serves the challenge UI from this path
	ChallengeUIPath string `json:"challenge_ui_path,omitempty"`

	log            *zap.Logger
	sessionBackend session.Backend
	cookieConfig   *CookieConfig
}

// CaddyModule returns the Caddy module information
func (VerifyHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.altcha_verify",
		New: func() caddy.Module { return new(VerifyHandler) },
	}
}

// StoredRequest represents a saved request
type StoredRequest struct {
	Method    string              `json:"method"`
	URL       string              `json:"url"`
	Headers   map[string][]string `json:"headers"`
	Body      []byte              `json:"body"`
	ReturnURI string              `json:"return_uri,omitempty"`
}

// Provision sets up the verify handler
func (h *VerifyHandler) Provision(ctx caddy.Context) error {
	h.log = ctx.Logger(h)

	// Set defaults
	if h.SessionBackendURI == "" {
		h.SessionBackendURI = "memory://"
	}
	if h.SessionTTL == 0 {
		h.SessionTTL = caddy.Duration(5 * time.Minute)
	}
	if h.VerifyFieldName == "" {
		h.VerifyFieldName = "altcha"
	}
	if h.ChallengeRedirect == "" {
		h.ChallengeRedirect = "/captcha"
	}

	// Initialize session backend
	backend, err := session.NewBackend(h.SessionBackendURI)
	if err != nil {
		return fmt.Errorf("failed to initialize session backend: %w", err)
	}
	h.sessionBackend = backend

	// Configure cookie
	h.cookieConfig = &CookieConfig{
		Name:     h.VerifiedCookieName,
		TTL:      h.VerifiedCookieTTL,
		Path:     h.VerifiedCookiePath,
		Domain:   h.VerifiedCookieDomain,
		Secure:   h.VerifiedCookieSecure,
		HTTPOnly: h.VerifiedCookieHTTPOnly,
		SameSite: h.VerifiedCookieSameSite,
	}
	h.cookieConfig.SetDefaults()

	h.log.Info("provisioning ALTCHA verify handler",
		zap.String("session_backend", h.SessionBackendURI),
		zap.Duration("session_ttl", time.Duration(h.SessionTTL)),
		zap.String("challenge_redirect", h.ChallengeRedirect),
		zap.Bool("preserve_post_data", h.PreservePostData),
	)

	return nil
}

// Validate ensures the configuration is valid
func (h *VerifyHandler) Validate() error {
	if h.HMACKey == "" {
		return fmt.Errorf("hmac_key is required")
	}

	if len(h.HMACKey) < 32 {
		h.log.Warn("HMAC key shorter than recommended 32 bytes",
			zap.Int("length", len(h.HMACKey)))
	}

	if time.Duration(h.SessionTTL) < time.Minute {
		return fmt.Errorf("session_ttl must be at least 1 minute")
	}

	return nil
}

// Cleanup closes the session backend
func (h *VerifyHandler) Cleanup() error {
	if h.sessionBackend != nil {
		return h.sessionBackend.Close()
	}
	return nil
}

// ServeHTTP verifies ALTCHA solutions
func (h *VerifyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Check if verification is needed
	if !h.needsVerification(r) {
		h.log.Debug("verification not needed, skipping",
			zap.String("path", r.URL.Path),
			zap.String("client_ip", r.RemoteAddr))
		return next.ServeHTTP(w, r)
	}

	// Check if already verified via cookie
	if h.hasValidVerificationCookie(r) {
		h.log.Debug("valid verification cookie found",
			zap.String("path", r.URL.Path))
		return next.ServeHTTP(w, r)
	}

	// Check for ALTCHA solution in request
	solution := h.extractSolution(r)
	if solution == "" {
		h.log.Debug("no solution found, redirecting to challenge",
			zap.String("path", r.URL.Path))
		return h.redirectToChallenge(w, r)
	}

	// Verify the solution
	valid, err := h.verifySolution(solution)
	if err != nil {
		h.log.Error("verification failed", zap.Error(err))
		return h.redirectToChallenge(w, r)
	}

	if !valid {
		h.log.Warn("invalid ALTCHA solution",
			zap.String("path", r.URL.Path),
			zap.String("client_ip", r.RemoteAddr))
		return h.redirectToChallenge(w, r)
	}

	// Set verification cookie
	cookieValue, err := GenerateCookieValue()
	if err != nil {
		h.log.Error("failed to generate cookie value", zap.Error(err))
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	h.cookieConfig.SetCookie(w, cookieValue)

	h.log.Info("ALTCHA verification successful",
		zap.String("path", r.URL.Path),
		zap.String("client_ip", r.RemoteAddr))

	// Check for session ID (contains return URI and optional POST data)
	if sessionID := r.URL.Query().Get("session"); sessionID != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		
		data, err := h.sessionBackend.Get(ctx, sessionID)
		if err != nil {
			h.log.Warn("failed to retrieve session", zap.Error(err))
			return next.ServeHTTP(w, r)
		}
		
		// Delete session after retrieval (one-time use)
		go h.sessionBackend.Delete(context.Background(), sessionID)
		
		var storedReq StoredRequest
		if err := json.Unmarshal(data, &storedReq); err != nil {
			h.log.Error("failed to unmarshal session data", zap.Error(err))
			return next.ServeHTTP(w, r)
		}
		
		// Get return URI from session (secure - not from URL parameter)
		returnURI := storedReq.ReturnURI
		if returnURI != "" {
			// Validate it's safe even though it came from our session (defense in depth)
			if h.isSafeRedirect(returnURI, r.Host) {
				h.log.Debug("redirecting to original URI from session",
					zap.String("return_uri", returnURI))
				
				// If POST data was preserved, restore and continue
				if storedReq.Method == "POST" && len(storedReq.Body) > 0 {
					r.Method = storedReq.Method
					r.Body = io.NopCloser(bytes.NewBuffer(storedReq.Body))
					for key, values := range storedReq.Headers {
						r.Header[key] = values
					}
					h.log.Debug("restored POST data from session")
					return next.ServeHTTP(w, r)
				}
				
				// For GET requests, redirect to clean URL
				http.Redirect(w, r, returnURI, http.StatusSeeOther)
				return nil
			}
			h.log.Warn("unsafe return URI rejected from session",
				zap.String("return_uri", returnURI),
				zap.String("host", r.Host))
		}
	}

	return next.ServeHTTP(w, r)
}

// needsVerification checks if verification is required
func (h *VerifyHandler) needsVerification(r *http.Request) bool {
	// Check Coraza environment variable
	if h.CorazaEnvVar != "" {
		if val := os.Getenv(h.CorazaEnvVar); val == "1" || val == "true" {
			return true
		}
	}

	// Default: always verify
	return true
}

// hasValidVerificationCookie checks for a valid verification cookie
func (h *VerifyHandler) hasValidVerificationCookie(r *http.Request) bool {
	cookie, err := h.cookieConfig.GetCookie(r)
	if err != nil {
		return false
	}

	// Cookie exists and has a value
	return cookie.Value != ""
}

// extractSolution gets the ALTCHA solution from the request
func (h *VerifyHandler) extractSolution(r *http.Request) string {
	// Check query parameter
	if solution := r.URL.Query().Get(h.VerifyFieldName); solution != "" {
		return solution
	}

	// Check form data
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			return r.FormValue(h.VerifyFieldName)
		}
	}

	// Check header
	return r.Header.Get("X-Altcha-Solution")
}

// verifySolution verifies an ALTCHA solution
func (h *VerifyHandler) verifySolution(payload string) (bool, error) {
	return altcha.VerifySolution(payload, h.HMACKey, true)
}

// redirectToChallenge redirects to the challenge page
func (h *VerifyHandler) redirectToChallenge(w http.ResponseWriter, r *http.Request) error {
	originalURI := r.URL.RequestURI()
	
	// Generate session ID for this verification flow
	sessionID, err := GenerateSessionID()
	if err != nil {
		h.log.Error("failed to generate session ID", zap.Error(err))
		// Fallback: redirect without session
		http.Redirect(w, r, h.ChallengeRedirect, http.StatusSeeOther)
		return nil
	}
	
	// Always store return URI in session (secure approach)
	storedReq := StoredRequest{
		ReturnURI: originalURI,
	}
	
	// For POST requests, also store request data if configured
	if r.Method == http.MethodPost && h.PreservePostData {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			h.log.Error("failed to read request body", zap.Error(err))
		} else {
			r.Body = io.NopCloser(bytes.NewBuffer(body))
			storedReq.Method = r.Method
			storedReq.URL = r.URL.String()
			storedReq.Headers = r.Header
			storedReq.Body = body
		}
	}
	
	// Marshal and store in session backend
	data, err := json.Marshal(storedReq)
	if err != nil {
		h.log.Error("failed to marshal session data", zap.Error(err))
		http.Redirect(w, r, h.ChallengeRedirect, http.StatusSeeOther)
		return nil
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	if err := h.sessionBackend.Store(ctx, sessionID, data, time.Duration(h.SessionTTL)); err != nil {
		h.log.Error("failed to store session", zap.Error(err))
		http.Redirect(w, r, h.ChallengeRedirect, http.StatusSeeOther)
		return nil
	}
	
	// Only session ID in URL (return URI is stored server-side)
	redirectURL := fmt.Sprintf("%s?session=%s", h.ChallengeRedirect, sessionID)
	
	h.log.Debug("redirecting to challenge with session",
		zap.String("session_id", sessionID),
		zap.String("original_uri", originalURI),
		zap.Bool("has_post_data", storedReq.Method == "POST"))
	
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
	return nil
}

// isSafeRedirect validates that a redirect URI is safe (same-origin)
func (h *VerifyHandler) isSafeRedirect(redirectURI string, currentHost string) bool {
	// Must be relative URL starting with /
	if !strings.HasPrefix(redirectURI, "/") {
		return false
	}

	// Protocol-relative URLs (//evil.com) are dangerous
	if strings.HasPrefix(redirectURI, "//") {
		return false
	}

	// Check for null bytes, newlines, or other control characters
	if strings.ContainsAny(redirectURI, "\x00\r\n") {
		return false
	}

	return true
}

// UnmarshalCaddyfile sets up the handler from Caddyfile
func (h *VerifyHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		// Check for matcher
		if d.NextArg() {
			// Matcher is handled by Caddy's route system
		}

		for d.NextBlock(0) {
			switch d.Val() {
			case "hmac_key":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.HMACKey = d.Val()

			case "session_backend":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.SessionBackendURI = d.Val()

			case "session_ttl":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid session_ttl: %v", err)
				}
				h.SessionTTL = caddy.Duration(dur)

			case "verified_cookie_name":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.VerifiedCookieName = d.Val()

			case "verified_cookie_ttl":
				if !d.NextArg() {
					return d.ArgErr()
				}
				var ttl int
				if _, err := fmt.Sscanf(d.Val(), "%d", &ttl); err != nil {
					return d.Errf("invalid verified_cookie_ttl: %v", err)
				}
				h.VerifiedCookieTTL = ttl

			case "verified_cookie_secure":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.VerifiedCookieSecure = d.Val() == "true"

			case "verified_cookie_http_only":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.VerifiedCookieHTTPOnly = d.Val() == "true"

			case "verified_cookie_same_site":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.VerifiedCookieSameSite = d.Val()

			case "challenge_redirect":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.ChallengeRedirect = d.Val()

			case "preserve_post_data":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.PreservePostData = d.Val() == "true"

			case "coraza_env_var":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.CorazaEnvVar = d.Val()

			case "verify_field_name":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.VerifyFieldName = d.Val()

			default:
				return d.Errf("unknown subdirective: %s", d.Val())
			}
		}
	}

	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*VerifyHandler)(nil)
	_ caddy.Validator             = (*VerifyHandler)(nil)
	_ caddy.CleanerUpper          = (*VerifyHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*VerifyHandler)(nil)
	_ caddyfile.Unmarshaler       = (*VerifyHandler)(nil)
)
