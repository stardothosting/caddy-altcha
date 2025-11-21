# Laravel WAF-as-a-Service Integration: ALTCHA Security Updates

## Overview

The Caddy ALTCHA module has been updated with critical security enhancements. These changes add **optional** configuration fields that strengthen security without breaking existing implementations. This document explains what changed and how to integrate these options into your Laravel-based WAF management system.

---

## Change Summary

### What Changed
1. **CORS Origin Validation** - New optional field for `altcha_verify_solution` handler
2. **Rate Limiting** - New optional fields for `altcha_challenge` handler  
3. **Security Hardening** - Internal improvements (no config changes needed)

### Backward Compatibility
- **ALL NEW FIELDS ARE OPTIONAL**
- **EXISTING CONFIGS WORK WITHOUT CHANGES**
- **DEFAULTS MAINTAIN CURRENT BEHAVIOR**

If you do nothing, your existing Caddy configurations will continue to work exactly as before.

---

## New Configuration Fields

### 1. CORS Origin Restriction (High Priority - Recommended)

**Handler**: `altcha_verify_solution` (if used)

**New Optional Fields**:
```json
{
  "handler": "altcha_verify_solution",
  "hmac_key": "...",
  "allowed_origins": [
    "https://yourdomain.com",
    "https://www.yourdomain.com"
  ]
}
```

**Purpose**: Restricts which websites can use your ALTCHA challenges. Prevents resource abuse.

**Laravel Database Schema Addition** (if storing this config):
```php
// Migration example (if you store handler configs in database)
Schema::table('caddy_handlers', function (Blueprint $table) {
    $table->json('allowed_origins')->nullable()->after('hmac_key');
});
```

**Default Behavior if Omitted**: 
- Allows all origins (wildcard `*`) - backward compatible
- Logs warning: "CORS wildcard in use - configure allowed_origins for security"

**When to Use**:
- Always use in production
- Only skip if you intentionally want any website to use your challenges

---

### 2. Rate Limiting (Medium Priority - Recommended)

**Handler**: `altcha_challenge`

**New Optional Fields**:
```json
{
  "handler": "altcha_challenge",
  "hmac_key": "...",
  "algorithm": "SHA-256",
  "max_number": 1000000,
  "expires": "5m",
  "rate_limit_requests": 10,
  "rate_limit_window": "1m"
}
```

**Purpose**: Prevents DoS attacks via excessive challenge generation.

**Laravel Database Schema Addition**:
```php
// Migration example
Schema::table('caddy_handlers', function (Blueprint $table) {
    $table->integer('rate_limit_requests')->nullable()->default(0);
    $table->string('rate_limit_window')->nullable()->default('1m');
});
```

**Default Behavior if Omitted**:
- No rate limiting (unlimited requests) - backward compatible
- `rate_limit_requests: 0` explicitly disables

**Recommended Values**:
- Development: `0` (disabled)
- Production: `10-20` requests per minute
- High-traffic: `50-100` requests per minute

---

## Laravel Integration Guide

### Minimal Impact Approach (Recommended)

Add new fields as **optional** in your existing config builder:

```php
// Example: Caddy config builder method
public function buildAltchaChallengeConfig(array $userSettings): array
{
    $config = [
        'handler' => 'altcha_challenge',
        'hmac_key' => $this->getHmacKey(),
        'algorithm' => $userSettings['algorithm'] ?? 'SHA-256',
        'max_number' => $userSettings['max_number'] ?? 1000000,
        'expires' => $userSettings['expires'] ?? '5m',
    ];

    // NEW: Add rate limiting if configured (optional)
    if (!empty($userSettings['rate_limit_requests'])) {
        $config['rate_limit_requests'] = (int)$userSettings['rate_limit_requests'];
        $config['rate_limit_window'] = $userSettings['rate_limit_window'] ?? '1m';
    }

    return $config;
}

public function buildAltchaVerifySolutionConfig(array $userSettings): array
{
    $config = [
        'handler' => 'altcha_verify_solution',
        'hmac_key' => $this->getHmacKey(),
    ];

    // NEW: Add CORS origins if configured (optional)
    if (!empty($userSettings['allowed_origins'])) {
        $config['allowed_origins'] = $userSettings['allowed_origins'];
    }

    return $config;
}
```

### UI/Form Additions (Optional - Progressive Enhancement)

If you want to expose these settings in your Laravel admin UI:

```php
// Example validation rules
public function altchaConfigRules(): array
{
    return [
        'max_number' => 'nullable|integer|min:1000',
        'rate_limit_requests' => 'nullable|integer|min:0|max:1000',
        'rate_limit_window' => 'nullable|string|regex:/^\d+(s|m|h)$/',
        'allowed_origins' => 'nullable|array',
        'allowed_origins.*' => 'url',
    ];
}
```

```blade
<!-- Example Blade form fields (progressive enhancement) -->
<div class="form-group">
    <label>Rate Limiting (Optional)</label>
    <input type="number" name="rate_limit_requests" 
           placeholder="0 = disabled, 10-20 recommended">
    <small>Max challenges per IP per time window</small>
</div>

<div class="form-group">
    <label>Rate Limit Window</label>
    <input type="text" name="rate_limit_window" 
           value="1m" placeholder="1m, 5m, 1h">
</div>

<div class="form-group">
    <label>Allowed Origins (Optional, one per line)</label>
    <textarea name="allowed_origins[]" rows="3">
https://{{ $domain }}
https://www.{{ $domain }}
    </textarea>
    <small>Leave empty to allow all origins (less secure)</small>
</div>
```

---

## No-Code-Change Option

If you don't want to modify your Laravel codebase immediately:

1. **Do Nothing** - All existing configs continue to work
2. **Add Fields Later** - When you're ready, add the optional fields to your UI
3. **Manual Override** - For high-security customers, manually add fields to their Caddy JSON

The module will use sensible defaults (backward-compatible with current behavior).

---

## Testing Your Integration

### 1. Verify Existing Configs Still Work

```bash
# Deploy updated Caddy module
./caddy validate --config existing-config.json

# Should show no errors
```

### 2. Test Rate Limiting

```json
{
  "handler": "altcha_challenge",
  "hmac_key": "test-key",
  "max_number": 1000000,
  "rate_limit_requests": 5,
  "rate_limit_window": "1m"
}
```

```bash
# Should return 200 for first 5 requests
for i in {1..5}; do curl -i http://localhost/api/altcha/challenge; done

# 6th request should return 429 Too Many Requests
curl -i http://localhost/api/altcha/challenge
# HTTP/1.1 429 Too Many Requests
```

### 3. Test CORS Restriction

```json
{
  "handler": "altcha_verify_solution",
  "hmac_key": "test-key",
  "allowed_origins": ["https://allowed.com"]
}
```

```bash
# Allowed origin - should work
curl -H "Origin: https://allowed.com" \
     -X POST http://localhost/api/altcha/verify \
     -d '{"payload":"..."}'

# Blocked origin - should return 403
curl -H "Origin: https://evil.com" \
     -X POST http://localhost/api/altcha/verify \
     -d '{"payload":"..."}'
# {"error":"origin not allowed"}
```

---

## Recommended Rollout Strategy

### Phase 1: Internal Testing (Week 1)
- Deploy updated Caddy module to staging
- Verify existing configs work without changes
- Test new optional fields manually

### Phase 2: Progressive Enhancement (Week 2-3)
- Add database migrations for new fields
- Update config builder to include optional fields
- Add UI forms (if desired)
- Deploy to 1-2 pilot customers

### Phase 3: Production Rollout (Week 4+)
- Enable rate limiting for all new customers (default: 10 req/min)
- Add CORS restriction for all customers (use their domain)
- Gradually backfill existing customers

---

## Customer Communication Template

**Subject**: Enhanced ALTCHA Security Features Available

**Body**:
> We've updated our ALTCHA captcha module with enhanced security features:
>
> **Rate Limiting** - Protects against DoS attacks by limiting challenge generation  
> **CORS Restriction** - Prevents unauthorized sites from using your challenges
>
> **Action Required**: None - your existing configuration continues to work.
>
> **Optional Upgrade**: Contact support to enable enhanced security for your account.
>
> These features strengthen your captcha implementation without any disruption to your current setup.

---

## Configuration Examples

### Minimal (Backward Compatible)
```json
{
  "handler": "altcha_challenge",
  "hmac_key": "{env.ALTCHA_HMAC_KEY}",
  "algorithm": "SHA-256",
  "max_number": 1000000
}
```

### Enhanced Security (Recommended)
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
  "handler": "altcha_verify_solution",
  "hmac_key": "{env.ALTCHA_HMAC_KEY}",
  "allowed_origins": [
    "https://customer-domain.com",
    "https://www.customer-domain.com"
  ]
}
```

### High-Security (Strict)
```json
{
  "handler": "altcha_challenge",
  "hmac_key": "{env.ALTCHA_HMAC_KEY}",
  "algorithm": "SHA-384",
  "max_number": 10000000,
  "expires": "3m",
  "rate_limit_requests": 5,
  "rate_limit_window": "1m"
}
```

---

## Database Schema Reference

If you're storing Caddy configs in a database:

```sql
-- Add columns to existing handler config table
ALTER TABLE caddy_handlers 
ADD COLUMN rate_limit_requests INT DEFAULT 0,
ADD COLUMN rate_limit_window VARCHAR(10) DEFAULT '1m',
ADD COLUMN allowed_origins JSON;

-- Example data
UPDATE caddy_handlers 
SET rate_limit_requests = 10,
    rate_limit_window = '1m',
    allowed_origins = '["https://example.com", "https://www.example.com"]'
WHERE handler_type = 'altcha_challenge'
AND customer_id = 123;
```

---

## FAQs

**Q: Do I need to update all existing customer configs?**  
A: No. Existing configs work without changes. New fields are optional.

**Q: What happens if I don't set `allowed_origins`?**  
A: The module allows all origins (wildcard) for backward compatibility. You'll see a warning in logs.

**Q: Can I disable rate limiting?**  
A: Yes. Set `rate_limit_requests: 0` or omit the field entirely.

**Q: Will this break customer widgets?**  
A: No. All changes are backward compatible. Widgets work exactly as before.

**Q: Should I force all customers to use these new features?**  
A: No. Offer as optional security enhancement. Enable by default for new customers.

**Q: How do I test without affecting production?**  
A: Deploy to staging first, test with your own domains, verify logs show expected behavior.

---

## Support

If you encounter issues integrating these changes:

1. **Check Logs**: Look for "CORS wildcard in use" or "rate limit exceeded" messages
2. **Validate JSON**: Ensure new fields are properly formatted
3. **Test Incrementally**: Add one feature at a time
4. **Contact**: Reference commit hash `[COMMIT_HASH]` when reporting issues

---

## Summary

- ✅ **Zero Breaking Changes** - All existing configs work
- ✅ **Optional Features** - Enable only if desired
- ✅ **Backward Compatible** - Defaults maintain current behavior
- ✅ **Progressive Enhancement** - Add features incrementally
- ✅ **Customer-Friendly** - No forced upgrades

**Recommended Next Step**: Deploy updated Caddy binary, verify existing configs work, then progressively add new fields to your Laravel UI.

