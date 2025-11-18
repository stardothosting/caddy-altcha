#!/bin/bash
# Test script to demonstrate ALTCHA is entirely self-contained

set -e

echo "=================================="
echo "ALTCHA Self-Contained Test"
echo "=================================="
echo ""
echo "This script proves that ALTCHA runs entirely"
echo "within your Caddy server with NO external services."
echo ""

# Check if caddy is built
if [ ! -f "../caddy" ]; then
    echo "❌ Caddy binary not found. Building..."
    cd ..
    xcaddy build --with github.com/shift8-projects/caddy-altcha=.
    cd examples
    echo "✅ Caddy built successfully"
fi

# Create test Caddyfile
cat > Caddyfile.test << 'EOF'
{
    admin off
    http_port 9999
}

localhost:9999 {
    # This endpoint is handled by YOUR module, not an external service
    route /api/altcha/challenge {
        altcha_challenge {
            hmac_key test-key-minimum-32-characters-long
            algorithm SHA-256
            max_number 50000
            expires 5m
        }
    }
    
    # Simple challenge page for testing
    route /captcha {
        respond 200 {
            body `<!DOCTYPE html>
<html>
<head>
    <title>ALTCHA Test</title>
    <script type="module" src="https://cdn.jsdelivr.net/npm/altcha/dist/altcha.min.js"></script>
</head>
<body style="font-family: sans-serif; padding: 50px;">
    <h1>✅ ALTCHA Running in Your Caddy</h1>
    <p><strong>No external ALTCHA service needed!</strong></p>
    <p>The challenge endpoint below is handled by your Caddy module:</p>
    <div style="background: #f0f0f0; padding: 10px; margin: 20px 0;">
        <code>GET http://localhost:9999/api/altcha/challenge</code>
    </div>
    
    <h2>Live Challenge</h2>
    <altcha-widget
        challengeurl="/api/altcha/challenge"
        hidefooter="false"
    ></altcha-widget>
    
    <div id="status" style="margin-top: 20px; padding: 10px; background: #e0e0e0;"></div>
    
    <script>
        const widget = document.querySelector('altcha-widget');
        const status = document.getElementById('status');
        
        widget.addEventListener('statechange', (ev) => {
            status.innerHTML = 'Status: ' + ev.detail.state;
            if (ev.detail.state === 'verified') {
                status.style.background = '#90EE90';
                status.innerHTML += '<br><strong>✅ Solution verified by YOUR Caddy module!</strong>';
            }
        });
    </script>
</body>
</html>`
        }
    }
    
    # Protected endpoint
    @protected {
        path /admin
    }
    
    altcha_verify @protected {
        hmac_key test-key-minimum-32-characters-long
        session_backend memory://
        challenge_redirect /captcha
    }
    
    respond /admin "✅ You're verified! This was all handled by your Caddy module." 200
    respond / "Visit /captcha to see ALTCHA in action, or /admin to test verification" 200
}
EOF

echo "Starting Caddy on http://localhost:9999"
echo ""
echo "Test URLs:"
echo "  - http://localhost:9999/         (info page)"
echo "  - http://localhost:9999/captcha  (challenge UI)"
echo "  - http://localhost:9999/admin    (protected, requires verification)"
echo ""
echo "Test the challenge endpoint directly:"
echo "  curl http://localhost:9999/api/altcha/challenge"
echo ""
echo "Press Ctrl+C to stop"
echo ""

../caddy run --config Caddyfile.test

