package caddyaltcha

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	caddy.RegisterModule(ChallengeHandler{})
	caddy.RegisterModule(VerifyHandler{})

	httpcaddyfile.RegisterHandlerDirective("altcha_challenge", parseCaddyfile)
	httpcaddyfile.RegisterHandlerDirective("altcha_verify", parseCaddyfile)
}

// parseCaddyfile registers the Caddyfile directives
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var handler caddyhttp.MiddlewareHandler

	switch h.Val() {
	case "altcha_challenge":
		ch := new(ChallengeHandler)
		err := ch.UnmarshalCaddyfile(h.Dispenser)
		if err != nil {
			return nil, err
		}
		handler = ch
	case "altcha_verify":
		vh := new(VerifyHandler)
		err := vh.UnmarshalCaddyfile(h.Dispenser)
		if err != nil {
			return nil, err
		}
		handler = vh
	}

	return handler, nil
}
