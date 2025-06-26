# 🔐 OIDC Security Checks - Comprehensive Documentation

This document centralizes all security validations performed in the OIDC authentication flow, clearly documenting what is handled by Passport.js versus cust## 🔍 Testing Security

1. **PKCE Flow**: Test with incorrect code verifier (custom validation)
2. **JWT Tampering**: Test with modified JWT signature (Passport.js validation)
3. **Expired Tokens**: Test with expired ID tokens (Passport.js validation)
4. **Invalid Issuer**: Test with tokens from wrong issuer (Passport.js validation)
5. **State Parameter**: Test with modified/missing state (Passport.js validation)
6. **Nonce Validation**: Test with modified ID token nonce (Passport.js validation)

## 🔧 Recent Updates (June 26, 2025)

### Version Compatibility Issue Resolved ✅
- **Problem**: TypeScript compilation error with `nonce: true` (Type 'boolean' not assignable to 'string')
- **Root Cause**: Version mismatch between `passport-openidconnect@0.1.1` and `@types/passport-openidconnect@0.1.3`
- **Solution**: Updated `passport-openidconnect` to version `0.1.2`
- **Result**: All TypeScript errors resolved, nonce validation fully operational

### Current System Status ✅
- ✅ **Backend Compilation**: No TypeScript errors
- ✅ **Service Status**: Frontend (port 4200) and Backend (port 5000) running
- ✅ **Authentication Flow**: All OIDC endpoints responding correctly
- ✅ **Security Validation**: All planned security checks operational
- ✅ **Mock OIDC Provider**: Fully functional for development
- ✅ **Dependencies**: All library versions compatible

### Library Versions
- `passport-openidconnect`: 0.1.2 (updated from 0.1.1)
- `@types/passport-openidconnect`: 0.1.3
- `passport`: 0.7.0
- `express`: 5.0.1
- `typeorm`: 0.3.20

---

**Last Updated**: June 26, 2025 - All security validations implemented and operational
**Security Review**: All validations implemented per OIDC/OAuth2 security best practices
**Version Notes**: Using passport-openidconnect@0.1.2 with full nonce support and @types/passport-openidconnect@0.1.3📋 Security Validation Matrix

| Security Check | Implementation | Location | Notes |
|---------------|----------------|----------|-------|
| **JWT Signature Verification** | ✅ Passport.js | `passport-openidconnect` | RS256/JWKS automatic validation |
| **JWT Expiration (exp)** | ✅ Passport.js | `passport-openidconnect` | Automatic validation |
| **JWT Not Before (nbf)** | ✅ Passport.js | `passport-openidconnect` | Automatic validation |
| **JWT Issued At (iat)** | ✅ Passport.js | `passport-openidconnect` | Automatic validation |
| **Issuer Validation (iss)** | ✅ Passport.js | `passport-openidconnect` | Automatic validation against config |
| **Audience Validation (aud)** | ✅ Passport.js | `passport-openidconnect` | Automatic validation against client_id |
| **JWKS Key Retrieval** | ✅ Passport.js | `passport-openidconnect` | Automatic JWKS endpoint handling |
| **State Parameter (CSRF)** | ✅ Passport.js | `passport-openidconnect` | Built-in state store management |
| **Nonce Validation** | ✅ Passport.js | `passport-openidconnect` | Automatic with `nonce: true` option |
| **OAuth Error Handling** | ✅ Passport.js | `passport-openidconnect` | Built-in error parsing and handling |
| **PKCE Code Verifier** | 🔧 Custom Logic | `security-validator.ts:validatePKCE()` | S256 challenge validation |
| **Authorization Code Format** | 🔧 Custom Logic | `security-validator.ts:validateAuthorizationCode()` | Basic format check |
| **ACR Values Support** | ✅ Passport.js | Configuration option | Authentication context class |

## 🔍 Detailed Security Implementation

### 1. JWT and Token Security (Passport.js Handled)

**Location**: Automatically handled by `passport-openidconnect` strategy in `/back/src/config/auth.ts`

```typescript
// Passport automatically validates:
// - JWT signature using JWKS from issuer
// - Token expiration (exp claim)
// - Token not-before (nbf claim)
// - Issued-at (iat claim)
// - Issuer (iss claim) against configured issuer
// - Audience (aud claim) against client_id
// - JWKS key rotation and caching
```

**What Passport Does:**
- Fetches JWKS from `{issuer}/.well-known/jwks.json`
- Verifies JWT signature using appropriate key from JWKS
- Validates all standard JWT claims (exp, nbf, iat, iss, aud)
- Handles key rotation automatically
- Rejects invalid or expired tokens

### 2. State Parameter Validation (Passport.js Handled)

**Location**: Automatically handled by `passport-openidconnect` strategy's built-in state store
**Called from**: Automatic during authentication flow

```typescript
// Passport automatically:
// - Generates cryptographically secure state parameter
// - Stores state in session using built-in state store
// - Validates state parameter on callback
// - Prevents CSRF attacks automatically
```

**Purpose**: Prevents CSRF attacks by ensuring the state parameter returned matches what was sent.

### 3. Nonce Validation (Passport.js Handled)

**Location**: Automatically handled by `passport-openidconnect` strategy with `nonce: true`
**Called from**: Automatic during authentication flow

```typescript
// Configuration in auth.ts:
new OpenIDConnectStrategy({
  // ...other options...
  nonce: true,  // Enables automatic nonce generation and validation
}, ...)
```

**Purpose**: Prevents token replay attacks by ensuring the nonce in the ID token matches the session.

## 🔄 Security Flow Overview

### 1. Login Initiation (`/api/auth/login`)

**Security Setup for Mock OIDC**:
```typescript
// Generate security parameters (still needed for mock)
const { codeVerifier, codeChallenge } = generatePKCE();
const nonce = generateNonce();
const state = generateState();

// Store in session for later validation
req.session.codeVerifier = codeVerifier;
req.session.nonce = nonce;
req.session.state = state;
```

**Security Setup for Real OIDC**:
```typescript
// Only PKCE needs manual generation (not supported by passport-openidconnect)
const { codeVerifier, codeChallenge } = generatePKCE();
req.session.codeVerifier = codeVerifier;
req.session.codeChallenge = codeChallenge;

// Passport.js handles state and nonce automatically
return passport.authenticate('oidc')(req, res, next);
```

**Authorization URL includes**:
- `state`: Generated and managed by Passport.js
- `nonce`: Generated and managed by Passport.js
- `code_challenge`: PKCE challenge (S256)
- `acr_values`: Authentication context (configured in strategy)

### 2. Authorization Callback (`/api/auth/callback`)

**Security Validation Order**:

1. **OAuth Error Check** (Custom)
   ```typescript
   if (req.query.error) {
     // Handle OAuth provider errors
   }
   ```

2. **Authorization Code Validation** (Custom)
   ```typescript
   validateAuthorizationCode(code);
   ```

3. **PKCE Validation** (Custom - Only check needed)
   ```typescript
   validatePKCE(req.session.codeVerifier, req.session.codeChallenge);
   ```

4. **All Other Security Validations** (Passport.js Automatic)
   ```typescript
   // Passport automatically handles:
   // - State parameter validation (CSRF protection)
   // - Token exchange and JWT validation
   // - JWT signature & claims validation
   // - Issuer & audience verification
   // - Token expiration checks
   // - Nonce validation (replay protection)
   ```

## 🚨 Error Handling

All security validation errors are categorized and handled appropriately:

```typescript
export interface SecurityValidationError extends Error {
  code: string;
  details?: any;
}
```

**Error Codes**:
- `PKCE_MISMATCH`: Code verifier validation failed
- `INVALID_AUTH_CODE`: Malformed authorization code

## 🏗️ File Structure

```
back/
├── src/
│   ├── config/
│   │   ├── auth.ts              # Passport.js OIDC strategy configuration
│   │   └── mock-auth.ts         # Mock OIDC provider setup
│   ├── controllers/
│   │   ├── AuthController.ts    # Main auth flow controller
│   │   └── MockOidcController.ts # Mock OIDC provider
│   ├── utils/
│   │   └── security-validator.ts # Custom security validations
│   ├── middleware/
│   │   └── security.ts          # Security headers & CORS
│   └── services/
│       └── AuthService.ts       # User authentication service
```

## 🔧 Configuration

**Environment Variables**:
```bash
# Real OIDC Provider
OIDC_CLIENT_ID=your-client-id
OIDC_CLIENT_SECRET=your-client-secret
OIDC_ISSUER=https://your-provider.com
OIDC_CALLBACK_URL=https://node.localhost/api/auth/callback
OIDC_ACR_VALUES=your-acr-value

# Mock OIDC (Development)
USE_MOCK_OIDC=true
NODE_ENV=development
```

## ✅ Security Best Practices Implemented

1. **Defense in Depth**: Multiple layers of validation with Passport.js + custom PKCE
2. **Fail Secure**: All validation failures redirect to login with generic error
3. **Session Security**: Secure cookie settings, session regeneration
4. **CSRF Protection**: Automatic state parameter validation via Passport.js
5. **Code Injection Prevention**: PKCE implementation (custom)
6. **Replay Attack Prevention**: Automatic nonce validation via Passport.js
7. **JWT Security**: Full Passport.js validation of all claims
8. **Key Rotation**: Automatic JWKS handling by Passport.js
9. **Error Handling**: Security-aware error responses
10. **Audit Trail**: Comprehensive logging of security events

## 📝 Maintenance Notes

- **Passport.js Updates**: Keep `passport-openidconnect` updated for latest security fixes
- **PKCE Validators**: Only PKCE validation remains custom (not supported by passport-openidconnect)
- **Error Monitoring**: Monitor security validation errors for attack patterns
- **Session Security**: Review session configuration in production
- **Key Rotation**: Verify JWKS endpoint accessibility and key rotation handling

## 🔍 Testing Security

1. **PKCE Flow**: Test with incorrect code verifier (custom validation)
2. **JWT Tampering**: Test with modified JWT signature (Passport.js validation)
3. **Expired Tokens**: Test with expired ID tokens (Passport.js validation)
4. **Invalid Issuer**: Test with tokens from wrong issuer (Passport.js validation)
5. **State Parameter**: Test with modified/missing state (Passport.js validation)
6. **Nonce Validation**: Test with modified ID token nonce (Passport.js validation)

---

**Last Updated**: Current implementation as of June 26, 2025 - All security validations implemented
**Security Review**: All validations implemented per OIDC/OAuth2 security best practices
**Version Notes**: Using passport-openidconnect@0.1.2 with full nonce support and @types/passport-openidconnect@0.1.3
