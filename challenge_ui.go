package caddyaltcha

// DefaultChallengeHTML provides a default challenge page
const DefaultChallengeHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification Required</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        .container {
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            max-width: 500px;
            width: 100%;
            padding: 40px;
            text-align: center;
        }
        
        .icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 24px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
        }
        
        h1 {
            color: #1a202c;
            font-size: 28px;
            margin-bottom: 12px;
            font-weight: 700;
        }
        
        p {
            color: #718096;
            font-size: 16px;
            line-height: 1.6;
            margin-bottom: 32px;
        }
        
        .altcha-container {
            margin: 32px 0;
            display: flex;
            justify-content: center;
        }
        
        #message {
            padding: 12px 20px;
            border-radius: 8px;
            margin-top: 20px;
            font-size: 14px;
            display: none;
        }
        
        #message.error {
            background: #fee;
            color: #c33;
            border: 1px solid #fcc;
        }
        
        #message.success {
            background: #efe;
            color: #3c3;
            border: 1px solid #cfc;
        }
        
        #message.info {
            background: #eef;
            color: #33c;
            border: 1px solid #ccf;
        }
        
        .loading {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 3px solid rgba(102, 126, 234, 0.3);
            border-radius: 50%;
            border-top-color: #667eea;
            animation: spin 1s ease-in-out infinite;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
        
        footer {
            margin-top: 32px;
            padding-top: 24px;
            border-top: 1px solid #e2e8f0;
            color: #a0aec0;
            font-size: 14px;
        }
        
        footer a {
            color: #667eea;
            text-decoration: none;
        }
        
        footer a:hover {
            text-decoration: underline;
        }
    </style>
    <script type="module" src="https://cdn.jsdelivr.net/npm/altcha/dist/altcha.min.js"></script>
</head>
<body>
    <div class="container">
        <div class="icon">🔒</div>
        <h1>Verification Required</h1>
        <p>Please complete the challenge below to continue. This helps us protect against automated abuse.</p>
        
        <div class="altcha-container">
            <altcha-widget
                challengeurl="/api/altcha/challenge"
                hidefooter="false"
                auto="onload"
            ></altcha-widget>
        </div>
        
        <div id="message"></div>
        
        <footer>
            Protected by <a href="https://altcha.org" target="_blank">ALTCHA</a>
        </footer>
    </div>
    
    <script>
        const widget = document.querySelector('altcha-widget');
        const message = document.getElementById('message');
        
        // Get session ID from URL if present (for POST data restoration)
        const urlParams = new URLSearchParams(window.location.search);
        const sessionId = urlParams.get('session');
        
        widget.addEventListener('statechange', (ev) => {
            if (ev.detail.state === 'verified') {
                message.textContent = 'Verification successful! Redirecting...';
                message.className = 'success';
                message.style.display = 'block';
                
                // Submit solution
                const payload = ev.detail.payload;
                
                // Build redirect URL with solution
                let redirectUrl = window.location.pathname;
                const params = new URLSearchParams();
                params.set('altcha', payload);
                if (sessionId) {
                    params.set('session', sessionId);
                }
                
                // Redirect to original page with solution
                // If session exists, the handler will restore POST data
                window.location.href = redirectUrl.replace('/captcha', '/') + '?' + params.toString();
            } else if (ev.detail.state === 'error') {
                message.textContent = 'Verification failed. Please try again.';
                message.className = 'error';
                message.style.display = 'block';
            }
        });
        
        // Show session restore info if present
        if (sessionId) {
            message.textContent = 'Your request has been saved. Complete the challenge to continue.';
            message.className = 'info';
            message.style.display = 'block';
        }
    </script>
</body>
</html>
`
