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
	HMACKey string `json:"hmac_key,omitempty"`
	log     *zap.Logger
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
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
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

	// Read raw body first
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		h.log.Error("failed to read body", zap.Error(err))
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"verified": false,
			"error":    err.Error(),
		})
		return nil
	}

	h.log.Debug("received verification request", zap.String("body", string(bodyBytes)))

	var req struct {
		Payload string `json:"payload"`
	}

	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		h.log.Error("failed to decode request", zap.Error(err), zap.String("raw_body", string(bodyBytes)))
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"verified": false,
			"error":    err.Error(),
		})
		return nil
	}

	// Verify the solution
	valid, err := altcha.VerifySolution(req.Payload, h.HMACKey, false)
	if err != nil {
		h.log.Error("verification failed", zap.Error(err), zap.String("payload", req.Payload))
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": err.Error(),
		})
		return nil
	}

	if !valid {
		h.log.Debug("solution invalid")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Solution verification failed",
		})
		return nil
	}

	// Return success - just an empty 200 OK or simple success indicator
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("{}"))
	return nil
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
