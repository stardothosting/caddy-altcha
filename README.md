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
- Automatic return URI preservation (users return to originally requested page)
- Coraza WAF integration support
- Secure cookie management with safe defaults
- Production-ready with comprehensive error handling

## Installation

Build Caddy with the ALTCHA module using a specific Caddy version (recommended for stability):

```bash
xcaddy build v2.8.4 --with github.com/stardothosting/caddy-altcha
```

Or build with the latest Caddy:

```bash
xcaddy build --with github.com/stardothosting/caddy-altcha
```

Or using Docker:

```bash
cd examples
docker-compose up
```

**Note:** Using a specific Caddy version (e.g., `v2.8.4`) prevents compatibility issues with newer Go versions and ensures build reproducibility.

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

## Widget Configuration

Create an HTML page with the ALTCHA widget (proof-of-work only):

```html
<!DOCTYPE html>
<html>
<head>
    <title>Verification Required</title>
    <script type="module" src="https://cdn.jsdelivr.net/npm/altcha@1.0.5/dist/altcha.min.js"></script>
</head>
<body>
    <h1>Verification Required</h1>
    <p>Please complete the challenge below.</p>
    
    <altcha-widget
        name="altcha"
        challengeurl="/api/altcha/challenge"
        hidefooter="false">
    </altcha-widget>
    
    <script>
        const widget = document.querySelector('altcha-widget');
        widget.addEventListener('statechange', (ev) => {
            if (ev.detail.state === 'verified') {
                const payload = ev.detail.payload;
                const urlParams = new URLSearchParams(window.location.search);
                const session = urlParams.get('session'); // Session ID contains return URI
                
                // Redirect with payload and session ID
                // Module will retrieve return URI from session server-side
                let redirectURL = `/?altcha=${encodeURIComponent(payload)}`;
                if (session) {
                    redirectURL += `&session=${encodeURIComponent(session)}`;
                }
                
                window.location.href = redirectURL;
            }
        });
    </script>
</body>
</html>
```

**With Code Challenges (optional visual CAPTCHA):**

```html
<script type="module" src="https://cdn.jsdelivr.net/npm/altcha@1.0.5/dist/altcha.min.js"></script>
<script type="module" src="https://cdn.jsdelivr.net/npm/altcha@1.0.5/obfuscation"></script>

<altcha-widget
    name="altcha"
    challengeurl="/api/altcha/challenge"
    plugins="obfuscation"
    hidefooter="false">
</altcha-widget>
```

**Important:** 
- Pin the widget version (e.g., `@1.0.5`) to prevent breaking changes
- Do NOT add `verifyurl` attribute for self-hosted mode
- The widget solves challenges client-side and passes the solution via URL/form

## Configuration Reference

### altcha_challenge

Generates cryptographic challenges for clients to solve.

```caddyfile
altcha_challenge {
    hmac_key <string>           # Required: HMAC secret key (min 32 chars recommended)
    algorithm <string>          # SHA-256, SHA-384, or SHA-512 (default: SHA-256)
    max_number <int>            # Maximum random number (default: 100000)
                                # Recommended: 1000000 (~200ms solve time)
    expires <duration>          # Challenge validity (default: 5m)
    salt_length <int>           # Salt length in bytes (default: 12)
    code_challenge <bool>       # Enable visual code challenges (default: false)
    code_length <int>           # Visual code length (default: 6, requires code_challenge: true)
    
    # Security (Optional)
    rate_limit_requests <int>   # Max requests per window (0 = disabled, default: 0)
    rate_limit_window <duration># Rate limit window (default: 1m)
}
```

**Difficulty Tuning (max_number):**
- `100000` - Very fast (~20ms solve time), light protection
- `1000000` - **Recommended** (~200ms solve time), good balance
- `10000000` - High security (~2s solve time), may frustrate users

**Code Challenges (Optional):**
- Set `code_challenge: true` to add visual code input on top of proof-of-work
- Similar to traditional CAPTCHAs but with computational challenge first
- Requires ALTCHA obfuscation plugin in your HTML (see Widget Configuration)

**Rate Limiting (Optional):**
- `rate_limit_requests: 10` - Max 10 challenges per IP per window
- `rate_limit_window: 1m` - Reset window duration
- Prevents DoS attacks via excessive challenge generation
- Returns HTTP 429 (Too Many Requests) when limit exceeded

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

### altcha_verify_solution (Optional)

Provides a dedicated endpoint for widget-based server-side verification. This is optional and only needed if you're using the ALTCHA widget with `verifyurl` attribute (typically for ALTCHA Sentinel cloud service).

```caddyfile
altcha_verify_solution {
    hmac_key <string>               # Required: Same key as altcha_challenge
    allowed_origins <string...>     # Allowed CORS origins (optional, restricts widget usage)
}
```

**CORS Security:**
- By default (no `allowed_origins`), allows requests from any origin (backward compatible)
- Configure `allowed_origins` to restrict which domains can use your challenges
- Example: `allowed_origins https://yourdomain.com https://test.yourdomain.com`
- Prevents unauthorized sites from consuming your server resources

## Security Best Practices

### Production Configuration

```json
{
  "handler": "altcha_challenge",
  "hmac_key": "{env.ALTCHA_HMAC_KEY}",
  "algorithm": "SHA-256",
  "max_number": 1000000,
  "expires": "5m",
  "rate_limit_requests": 10,
  "rate_limit_window": "1m"
}
```

```json
{
  "handler": "altcha_verify",
  "hmac_key": "{env.ALTCHA_HMAC_KEY}",
  "session_backend": "redis://localhost:6379",
  "session_ttl": "5m",
  "verified_cookie_secure": true,
  "verified_cookie_http_only": true,
  "verified_cookie_same_site": "Strict"
}
```

### HMAC Key Generation

```bash
# Generate cryptographically secure 256-bit key
openssl rand -base64 32

# Store in environment variable
export ALTCHA_HMAC_KEY="your-generated-key-here"
```

**Key Requirements:**
- Minimum 32 bytes (256 bits) for strong security
- Use `crypto/rand` or similar CSPRNG for generation
- Never hardcode keys in configuration files
- Rotate keys periodically (implement key rotation strategy)
- Store securely (environment variables, secrets manager, or vault)

### Rate Limiting

Protect against resource exhaustion attacks:

```caddyfile
altcha_challenge {
    hmac_key {env.ALTCHA_HMAC_KEY}
    max_number 1000000
    rate_limit_requests 10      # Max 10 challenges per IP
    rate_limit_window 1m        # Per 60-second window
}
```

**Recommendations:**
- Development: Disable rate limiting (`rate_limit_requests: 0`)
- Production: Start with `10-20 requests/minute`
- High-traffic: Increase to `50-100 requests/minute` if needed
- Monitor `429 Too Many Requests` responses to tune appropriately

### CORS Restriction

Prevent unauthorized widget usage:

```json
{
  "handler": "altcha_verify_solution",
  "hmac_key": "{env.ALTCHA_HMAC_KEY}",
  "allowed_origins": [
    "https://yourdomain.com",
    "https://www.yourdomain.com"
  ]
}
```

**Warning:** Without `allowed_origins`, any website can embed your challenge widget and consume your server resources.

### Session Security

```caddyfile
altcha_verify {
    session_backend redis://localhost:6379
    session_ttl 5m              # Short TTL reduces exposure window
    verified_cookie_secure true # HTTPS only
    verified_cookie_http_only true # Prevent XSS access
    verified_cookie_same_site Strict # Prevent CSRF
}
```

**Production Backend Recommendations:**
- **Memory**: Development only (sessions lost on restart)
- **File**: Simple deployments, single server
- **Redis**: Production, distributed deployments, high availability

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

## JSON Configuration for Production

For production deployments using JSON configuration (common in WAF-as-a-service setups):

### Complete Test Endpoint Example

```json
{
  "apps": {
    "http": {
      "servers": {
        "main": {
          "listen": [":443"],
          "routes": [
            {
              "match": [{"host": ["test.example.com"]}],
              "handle": [{
                "handler": "subroute",
                "routes": [
                  {
                    "match": [{
                      "path_regexp": {
                        "pattern": "^/api/altcha/challenge/?$"
                      }
                    }],
                    "handle": [{
                      "handler": "altcha_challenge",
                      "hmac_key": "{env.ALTCHA_HMAC_KEY}",
                      "algorithm": "SHA-256",
                      "max_number": 1000000,
                      "expires": "5m"
                    }],
                    "terminal": true
                  },
                  {
                    "match": [{
                      "path_regexp": {
                        "pattern": "^/captcha/?$"
                      }
                    }],
                    "handle": [
                      {
                        "handler": "rewrite",
                        "uri": "/index.html"
                      },
                      {
                        "handler": "file_server",
                        "root": "/var/www/altcha"
                      }
                    ],
                    "terminal": true
                  },
                  {
                    "match": [{
                      "path_regexp": {
                        "pattern": "^/protected/?$"
                      }
                    }],
                    "handle": [
                      {
                        "handler": "altcha_verify",
                        "hmac_key": "{env.ALTCHA_HMAC_KEY}",
                        "session_backend": "memory://",
                        "challenge_redirect": "/captcha",
                        "preserve_post_data": true
                      },
                      {
                        "handler": "static_response",
                        "body": "{\"success\": true, \"message\": \"Verification passed\"}"
                      }
                    ]
                  }
                ]
              }]
            }
          ]
        }
      }
    }
  }
}
```

**Important JSON Configuration Notes:**

- Use `path_regexp` with pattern `^/path/?$` to handle both `/path` and `/path/` (trailing slash)
- Set `terminal: true` for routes that should not fall through
- Use `rewrite` before `file_server` to serve index.html at /captcha
- Recommended `max_number: 1000000` for ~200ms solve time

### WAF-Protected Site Integration

For sites behind Coraza WAF, add ALTCHA routes to existing configurations:

```json
{
  "@id": "example.com",
  "match": [{"host": ["example.com"]}],
  "handle": [{
    "handler": "subroute",
    "routes": [
      {
        "@comment": "Coraza WAF - runs first",
        "handle": [{
          "handler": "waf",
          "directives": "SecComponentSignature \"WAF | example.com\"\nSecRuleEngine On\n..."
        }]
      },
      {
        "@comment": "ALTCHA Challenge Endpoint",
        "match": [{"path": ["/api/altcha/challenge"]}],
        "handle": [{
          "handler": "altcha_challenge",
          "hmac_key": "{env.ALTCHA_HMAC_KEY}",
          "algorithm": "SHA-256",
          "max_number": 100000,
          "expires": "5m"
        }]
      },
      {
        "@comment": "ALTCHA Challenge UI",
        "match": [{"path": ["/captcha"]}],
        "handle": [{
          "handler": "file_server",
          "root": "/var/www/altcha"
        }]
      },
      {
        "@comment": "Protected routes requiring ALTCHA",
        "match": [{"path": ["/login", "/register", "/api/submit"]}],
        "handle": [
          {
            "handler": "altcha_verify",
            "hmac_key": "{env.ALTCHA_HMAC_KEY}",
            "session_backend": "redis://localhost:6379/1",
            "session_ttl": "5m",
            "verified_cookie_name": "altcha_verified",
            "verified_cookie_ttl": 3600,
            "challenge_redirect": "/captcha",
            "preserve_post_data": true,
            "coraza_env_var": "altcha_required"
          },
          {
            "handler": "reverse_proxy",
            "upstreams": [{"dial": "backend:443"}]
          }
        ]
      },
      {
        "@comment": "Unprotected routes bypass ALTCHA",
        "handle": [{
          "handler": "reverse_proxy",
          "upstreams": [{"dial": "backend:443"}]
        }]
      }
    ]
  }],
  "terminal": true
}
```

### Deployment Steps

1. Generate HMAC key:

```bash
openssl rand -base64 32
```

2. Create challenge UI directory:

```bash
mkdir -p /var/www/altcha
```

3. Create `/var/www/altcha/index.html`:

```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification Required</title>
    <style>
        body {
            font-family: system-ui, -apple-system, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 2rem;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            max-width: 500px;
            text-align: center;
        }
        h1 { margin-top: 0; color: #333; }
        p { color: #666; line-height: 1.6; }
        #altcha-widget { margin: 2rem 0; }
        .error { color: #d32f2f; margin-top: 1rem; }
        .loading { color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Verification Required</h1>
        <p>Please complete the challenge below to continue.</p>
        
        <form id="altcha-form" method="POST">
            <div id="altcha-widget"></div>
            <div id="status" class="loading">Loading challenge...</div>
        </form>
    </div>

    <script type="module">
        import 'altcha' from 'https://cdn.jsdelivr.net/npm/altcha/dist/altcha.min.js';

        const widget = document.createElement('altcha-widget');
        widget.setAttribute('challengeurl', '/api/altcha/challenge');
        widget.setAttribute('auto', 'onload');
        
        document.getElementById('altcha-widget').appendChild(widget);
        document.getElementById('status').textContent = 'Solving challenge...';

        widget.addEventListener('statechange', (ev) => {
            const state = ev.detail.state;
            const status = document.getElementById('status');
            
            if (state === 'verified') {
                status.textContent = 'Verified! Redirecting...';
                status.style.color = '#2e7d32';
                
                const payload = ev.detail.payload;
                const urlParams = new URLSearchParams(window.location.search);
                const sessionId = urlParams.get('session');
                
                // Always include session ID - it contains the return URI
                let redirectUrl = `/?altcha=${encodeURIComponent(payload)}`;
                if (sessionId) {
                    redirectUrl += `&session=${encodeURIComponent(sessionId)}`;
                }
                
                setTimeout(() => window.location.href = redirectUrl, 500);
            } else if (state === 'error') {
                status.textContent = 'Verification failed. Please refresh and try again.';
                status.className = 'error';
            }
        });
    </script>
</body>
</html>
```

4. Set environment variable:

```bash
export ALTCHA_HMAC_KEY="your-generated-key-here"
```

5. Build Caddy with ALTCHA module:

```bash
xcaddy build --with github.com/stardothosting/caddy-altcha \
  --with github.com/corazawaf/coraza-caddy/v2
```

6. Load configuration:

```bash
caddy reload --config /path/to/config.json
```

7. Test endpoints:

```bash
# Health check
curl https://test.example.com/health

# Challenge generation
curl https://test.example.com/api/altcha/challenge

# Protected route (should redirect)
curl -I https://test.example.com/protected
```

### Notes on File Server Behavior

The `file_server` handler automatically serves `index.html` when a directory is requested. When configured with:

```json
{
  "handler": "file_server",
  "root": "/var/www/altcha"
}
```

Requesting `/captcha` will serve `/var/www/altcha/index.html`.

### HMAC Key Management

The HMAC key must be identical in both `altcha_challenge` and `altcha_verify` handlers. Options:

1. Environment variable (recommended):
```json
"hmac_key": "{env.ALTCHA_HMAC_KEY}"
```

2. Hardcoded (less secure, avoid in production):
```json
"hmac_key": "your-actual-key-here"
```

3. Per-site keys (for multi-tenant setups):
```json
"hmac_key": "{env.ALTCHA_HMAC_KEY_SITE1}"
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

### Automatic Return URI Preservation (Session-Based)

The module automatically preserves the original request URI when redirecting users to the challenge page. After solving the captcha, users are redirected back to their originally requested page.

**How it works:**

1. User requests `/wp-login.php` without verification
2. Module stores `/wp-login.php` in session backend (secure, server-side)
3. Module redirects to `/captcha?session=<session-id>` (only session ID in URL)
4. User solves challenge
5. Widget redirects to `/wp-login.php?altcha=<payload>&session=<session-id>`
6. Module retrieves return URI from session, verifies solution
7. Module redirects to clean `/wp-login.php` or continues request

**Security benefits:**
- Return URI stored server-side in session backend (not in URL)
- No URL parameter tampering possible
- Prevents open redirect attacks
- Session is one-time use (deleted after retrieval)

**No configuration needed** - this behavior is automatic. Sessions are required for this feature (use `memory://`, `file://`, or `redis://` backend).

### Redis Connection Failed

Check Redis is running and URI is correct:

```bash
redis-cli -u redis://localhost:6379/0 ping
```

### Blank Page at /captcha/

If `/captcha` works but `/captcha/` shows a blank page, your route isn't handling trailing slashes.

**Fix:** Use `path_regexp` in JSON config:

```json
{
  "match": [{
    "path_regexp": {
      "pattern": "^/captcha/?$"
    }
  }]
}
```

Or in Caddyfile, use wildcards:

```caddyfile
route /captcha* {
    rewrite * /index.html
    root * /var/www/altcha
    file_server
}
```

### Widget Shows "Verification Failed"

This usually indicates a protocol mismatch. Check:

```bash
# 1. Verify challenge endpoint returns correct JSON
curl https://example.com/api/altcha/challenge | jq

# Expected fields:
# - algorithm (string)
# - challenge (string - hex hash)
# - maxNumber (int - MUST be camelCase, not maxnumber!)
# - salt (string - hex)
# - signature (string - HMAC of challenge only)

# 2. Check browser console for errors
# 3. Verify widget is NOT using verifyurl attribute (self-hosted mode)
# 4. Hard refresh browser: Ctrl+Shift+R
```

## Development

### Build from Source

```bash
git clone https://github.com/stardothosting/caddy-altcha.git
cd caddy-altcha
go mod download
xcaddy build v2.8.4 --with github.com/stardothosting/caddy-altcha=.
```

### Run Tests

```bash
# Run all tests
make test

# Or run individually:
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
