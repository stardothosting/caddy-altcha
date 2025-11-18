# Caddy ALTCHA Module

Production-ready Caddy HTTP middleware module for ALTCHA captcha verification. Protects web applications from automated abuse using cryptographic proof-of-work challenges.

## Architecture

ALTCHA is entirely self-contained within your Caddy server. No separate ALTCHA service or external API calls are required. The module:

1. Generates cryptographic challenges via `/api/altcha/challenge` endpoint
2. Verifies solutions submitted by clients
3. Manages sessions using Memory, Redis, or File storage backends

The only external dependency is the ALTCHA JavaScript widget (can be self-hosted). All cryptographic operations happen within your Caddy module.

## Features

- Cryptographic protection using HMAC-signed proof-of-work challenges
- Sub-10ms verification latency
- Multiple storage backends (Redis, Memory, File)
- POST data preservation across verification redirects
- Coraza WAF integration support
- Secure cookie management with safe defaults
- Production-ready with comprehensive error handling

## Installation

Build Caddy with the ALTCHA module:

```bash
xcaddy build --with github.com/stardothosting/caddy-altcha
```

Or using Docker:

```bash
cd examples
docker-compose up
```

## Basic Configuration

Create a `Caddyfile`:

```caddyfile
{
    order altcha_verify before reverse_proxy
}

example.com {
    # Challenge generation endpoint
    route /api/altcha/challenge {
        altcha_challenge {
            hmac_key {env.ALTCHA_HMAC_KEY}
            algorithm SHA-256
            max_number 100000
            expires 5m
        }
    }
    
    # Challenge UI page
    route /captcha {
        root * /var/www/altcha
        file_server
    }
    
    # Protect specific routes
    @protected {
        path /login /register /api/*
    }
    
    altcha_verify @protected {
        hmac_key {env.ALTCHA_HMAC_KEY}
        session_backend memory://
        challenge_redirect /captcha
        preserve_post_data true
    }
    
    reverse_proxy localhost:8080
}
```

Set your HMAC key (minimum 32 characters):

```bash
export ALTCHA_HMAC_KEY="your-secret-key-min-32-chars-long"
```

Copy the example HTML to your web root:

```bash
cp examples/www/index.html /var/www/altcha/index.html
```

## Configuration Reference

### altcha_challenge

Generates cryptographic challenges for clients to solve.

```caddyfile
altcha_challenge {
    hmac_key <string>           # Required: HMAC secret key (min 32 chars recommended)
    algorithm <string>          # SHA-256, SHA-384, or SHA-512 (default: SHA-256)
    max_number <int>            # Maximum random number (default: 100000)
    expires <duration>          # Challenge validity (default: 5m)
    salt_length <int>           # Salt length in bytes (default: 12)
}
```

### altcha_verify

Verifies ALTCHA solutions and manages verification state.

```caddyfile
altcha_verify [<matcher>] {
    hmac_key <string>                  # Required: Same key as altcha_challenge
    session_backend <uri>              # Session storage (default: memory://)
    session_ttl <duration>             # Session validity (default: 5m)
    
    # Verification cookie configuration
    verified_cookie_name <string>      # Cookie name (default: altcha_verified)
    verified_cookie_ttl <int>          # Cookie TTL in seconds (default: 3600)
    verified_cookie_secure <bool>      # Secure flag (default: true)
    verified_cookie_http_only <bool>   # HttpOnly flag (default: true)
    verified_cookie_same_site <string> # SameSite: Strict, Lax, None (default: Strict)
    verified_cookie_path <string>      # Cookie path (default: /)
    verified_cookie_domain <string>    # Cookie domain (optional)
    
    # Behavior
    challenge_redirect <path>          # Challenge page path (default: /captcha)
    preserve_post_data <bool>          # Save POST data across redirects (default: false)
    verify_field_name <string>         # Form field with solution (default: altcha)
    
    # Integrations
    coraza_env_var <string>            # Environment variable set by Coraza
}
```

## Session Backends

### Memory (Development)

In-memory storage with LRU eviction:

```caddyfile
session_backend memory://
```

### Redis (Production)

Distributed storage with connection pooling:

```caddyfile
session_backend redis://localhost:6379/0
session_backend redis://:password@localhost:6379/0
```

### File (Simple Persistence)

File-based storage:

```caddyfile
session_backend file:///var/lib/caddy/altcha
```

## Usage Examples

### Protect Authentication Routes

```caddyfile
@auth {
    path /login /register /reset-password
}

altcha_verify @auth {
    hmac_key {env.ALTCHA_HMAC_KEY}
    session_backend redis://localhost:6379/0
    challenge_redirect /captcha
}
```

### Protect API with POST Preservation

```caddyfile
@api_post {
    path /api/*
    method POST
}

altcha_verify @api_post {
    hmac_key {env.ALTCHA_HMAC_KEY}
    preserve_post_data true
    challenge_redirect /captcha
}
```

### Skip Internal Traffic

```caddyfile
@external {
    not remote_ip 10.0.0.0/8 192.168.0.0/16
}

altcha_verify @external {
    hmac_key {env.ALTCHA_HMAC_KEY}
    challenge_redirect /captcha
}
```

## Coraza WAF Integration

Use Coraza to analyze requests and only challenge suspicious ones:

```caddyfile
{
    order coraza_waf before altcha_verify
    order altcha_verify before reverse_proxy
}

example.com {
    # Coraza analyzes requests
    coraza_waf {
        directives `
            Include /etc/coraza/crs-setup.conf
            Include /etc/coraza/rules/*.conf
            
            # Flag suspicious requests
            SecRule TX:ANOMALY_SCORE "@ge 5" \
                "id:1001,phase:2,pass,setenv:altcha_required=1"
        `
    }
    
    route /api/altcha/challenge {
        altcha_challenge {
            hmac_key {env.ALTCHA_HMAC_KEY}
        }
    }
    
    route /captcha {
        root * /var/www/altcha
        file_server
    }
    
    # Only challenge flagged requests
    altcha_verify {
        hmac_key {env.ALTCHA_HMAC_KEY}
        coraza_env_var altcha_required
        session_backend redis://localhost:6379/0
        challenge_redirect /captcha
    }
    
    reverse_proxy backend:8080
}
```

## Performance

- Verification latency: Sub-10ms per request
- Session capacity: 10,000+ concurrent sessions (memory backend)
- Redis pooling: MaxIdle 10, MaxActive 100
- Zero blocking operations in hot path

## Security

### Best Practices

1. Use cryptographically random HMAC keys (minimum 32 bytes)
2. Enable Secure, HttpOnly, and SameSite cookie flags
3. Set appropriate session TTLs (5-10 minutes recommended)
4. Always use HTTPS in production
5. Use authentication and TLS for Redis connections

### Key Generation

```bash
# Generate a secure HMAC key
openssl rand -base64 32
```

### Environment Variables

```bash
export ALTCHA_HMAC_KEY="$(openssl rand -base64 32)"
```

## Troubleshooting

### Challenge Not Loading

Check that the challenge endpoint is accessible:

```bash
curl https://example.com/api/altcha/challenge
```

### Verification Failing

Ensure HMAC keys match between challenge and verify handlers:

```caddyfile
# Both must use the same key
altcha_challenge {
    hmac_key {env.ALTCHA_HMAC_KEY}
}

altcha_verify {
    hmac_key {env.ALTCHA_HMAC_KEY}
}
```

### POST Data Lost

Enable POST data preservation:

```caddyfile
altcha_verify {
    preserve_post_data true
}
```

### Redis Connection Failed

Check Redis is running and URI is correct:

```bash
redis-cli -u redis://localhost:6379/0 ping
```

## Development

### Build from Source

```bash
git clone https://github.com/shift8-projects/caddy-altcha.git
cd caddy-altcha
go mod download
xcaddy build --with github.com/stardothosting/caddy-altcha=.
```

### Run Tests

```bash
go test ./...
go test -race ./...
go test -bench=. -benchmem
```

### Run Example

```bash
cd examples
export ALTCHA_HMAC_KEY="test-key-min-32-characters-long"
docker-compose up
```

Visit http://localhost/captcha to test the challenge UI.

## License

MIT License - see LICENSE file for details

## Credits

- [ALTCHA](https://altcha.org) - Proof-of-work captcha library
- [Caddy](https://caddyserver.com) - Web server and reverse proxy
- [caddy-defender](https://github.com/caddy-defender/caddy-defender) - Module architecture inspiration
