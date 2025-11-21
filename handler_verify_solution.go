package caddyaltcha

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/stardothosting/caddy-altcha/altcha"
)

// VerifySolutionHandler handles ALTCHA solution verification for the widget
type VerifySolutionHandler struct {
	HMACKey        string   `json:"hmac_key,omitempty"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	log            *zap.Logger
}

// CaddyModule returns the Caddy module information
func (VerifySolutionHandler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.altcha_verify_solution",
		New: func() caddy.Module { return new(VerifySolutionHandler) },
	}
}

// Provision sets up the handler
func (h *VerifySolutionHandler) Provision(ctx caddy.Context) error {
	h.log = ctx.Logger(h)
	return nil
}

// ServeHTTP handles the verification request from the ALTCHA widget
func (h *VerifySolutionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	// Set CORS headers with origin validation
	origin := r.Header.Get("Origin")
	
	// If allowed origins configured, validate origin
	if len(h.AllowedOrigins) > 0 {
		if origin != "" && h.isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		} else if origin != "" {
			// Origin not allowed - reject CORS request
			h.log.Warn("rejected CORS request from unauthorized origin", zap.String("origin", origin))
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "origin not allowed",
			})
			return nil
		}
	} else {
		// Backward compatibility: if no origins configured, allow all (with warning)
		h.log.Warn("CORS wildcard in use - configure allowed_origins for security")
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
	
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Content-Type", "application/json")

	// Handle OPTIONS preflight
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return nil
	}

	if r.Method != http.MethodPost {
		return caddyhttp.Error(http.StatusMethodNotAllowed, nil)
	}

	// Read raw body with size limit (4KB max)
	const maxPayloadSize = 4096
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxPayloadSize+1))
	if err != nil {
		h.log.Error("failed to read body", zap.Error(err))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "invalid_request",
		})
		return nil
	}

	// Check payload size
	if len(bodyBytes) > maxPayloadSize {
		h.log.Warn("oversized payload rejected", zap.Int("length", len(bodyBytes)))
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "payload_too_large",
		})
		return nil
	}

	// Log payload length only, not content (security)
	h.log.Debug("received verification request", zap.Int("body_length", len(bodyBytes)))

	var req struct {
		Payload string `json:"payload"`
	}

	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		h.log.Error("failed to decode request", zap.Error(err), zap.Int("body_length", len(bodyBytes)))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "invalid_request",
		})
		return nil
	}

	// Verify the solution
	valid, err := altcha.VerifySolution(req.Payload, h.HMACKey, false)
	if err != nil {
		// Log error details but return generic message (security)
		h.log.Error("verification failed", zap.Error(err), zap.Int("payload_length", len(req.Payload)))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "verification_failed",
		})
		return nil
	}

	if !valid {
		h.log.Debug("solution invalid", zap.Int("payload_length", len(req.Payload)))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "verification_failed",
		})
		return nil
	}

	// Return success - just an empty 200 OK or simple success indicator
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{}"))
	return nil
}

// isAllowedOrigin checks if an origin is in the allowed list
func (h *VerifySolutionHandler) isAllowedOrigin(origin string) bool {
	for _, allowed := range h.AllowedOrigins {
		if origin == allowed {
			return true
		}
	}
	return false
}

// UnmarshalCaddyfile parses the Caddyfile directive
func (h *VerifySolutionHandler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "hmac_key":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.HMACKey = d.Val()
			case "allowed_origins":
				h.AllowedOrigins = d.RemainingArgs()
				if len(h.AllowedOrigins) == 0 {
					return d.ArgErr()
				}
			default:
				return d.Errf("unknown subdirective: %s", d.Val())
			}
		}
	}
	return nil
}

// Interface guards
var (
	_ caddy.Provisioner           = (*VerifySolutionHandler)(nil)
	_ caddyhttp.MiddlewareHandler = (*VerifySolutionHandler)(nil)
	_ caddyfile.Unmarshaler       = (*VerifySolutionHandler)(nil)
)
