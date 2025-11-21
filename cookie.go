package caddyaltcha

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
)

// CookieConfig holds cookie configuration
type CookieConfig struct {
	Name     string `json:"name,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
	Path     string `json:"path,omitempty"`
	Domain   string `json:"domain,omitempty"`
	Secure   bool   `json:"secure,omitempty"`
	HTTPOnly bool   `json:"http_only,omitempty"`
	SameSite string `json:"same_site,omitempty"`
}

// SetDefaults applies secure defaults
func (c *CookieConfig) SetDefaults() {
	if c.Name == "" {
		c.Name = "altcha_verified"
	}
	if c.TTL == 0 {
		c.TTL = 3600
	}
	if c.Path == "" {
		c.Path = "/"
	}
	// Secure defaults
	c.Secure = true
	c.HTTPOnly = true
	if c.SameSite == "" {
		c.SameSite = "Strict"
	}
}

// GetSameSite converts string to http.SameSite
func (c *CookieConfig) GetSameSite() http.SameSite {
	switch c.SameSite {
	case "Lax", "lax":
		return http.SameSiteLaxMode
	case "None", "none":
		return http.SameSiteNoneMode
	case "Strict", "strict":
		return http.SameSiteStrictMode
	default:
		return http.SameSiteStrictMode
	}
}

// SetCookie creates and sets a verification cookie
func (c *CookieConfig) SetCookie(w http.ResponseWriter, value string) {
	cookie := &http.Cookie{
		Name:     c.Name,
		Value:    value,
		Path:     c.Path,
		Domain:   c.Domain,
		MaxAge:   c.TTL,
		Secure:   c.Secure,
		HttpOnly: c.HTTPOnly,
		SameSite: c.GetSameSite(),
	}

	http.SetCookie(w, cookie)
}

// GetCookie retrieves the verification cookie
func (c *CookieConfig) GetCookie(r *http.Request) (*http.Cookie, error) {
	return r.Cookie(c.Name)
}

// DeleteCookie removes the verification cookie
func (c *CookieConfig) DeleteCookie(w http.ResponseWriter) {
	cookie := &http.Cookie{
		Name:     c.Name,
		Value:    "",
		Path:     c.Path,
		Domain:   c.Domain,
		MaxAge:   -1,
		Secure:   c.Secure,
		HttpOnly: c.HTTPOnly,
		SameSite: c.GetSameSite(),
	}

	http.SetCookie(w, cookie)
}

// GenerateSessionID creates a cryptographically random session ID
// Uses hex encoding for consistent 64-character session IDs with full entropy
func GenerateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// GenerateCookieValue creates a random cookie value
func GenerateCookieValue() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}
