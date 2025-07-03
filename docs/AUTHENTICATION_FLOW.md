# 🔐 Complete Authentication Flow - Technical Documentation

## Overview
This application uses **OpenID Connect (OIDC)** with enhanced security features for authentication between an Angular frontend and Node.js/Express backend.

**Architecture:** Angular SPA ↔ Express/Node.js API ↔ OIDC Provider (Mock/Production)

---

## 🎯 **1. User Authentication Journey**

### **Step 1: User Visits Protected Route**
```
User → https://front.localhost/dashboard
```

**What Happens:**
1. Angular Router triggers `authGuard`
2. `authGuard` calls `AuthService.initialize()`
3. `AuthService` makes HTTP request to backend session endpoint
4. Backend returns unauthenticated session
5. `authGuard` redirects to `/auth/login`

**Frontend Code Flow:**
```typescript
// authGuard checks authentication
if (!authService.isAuthenticated()) {
  router.navigate(['/auth/login'], { queryParams: { returnTo: state.url } });
}
```

### **Step 2: User Clicks Login**
```
User clicks "Login" → AuthService.login() → Backend OIDC initiation
```

**Frontend Call:**
```typescript
login(returnTo?: string): void {
  const loginUrl = `${environment.apiUrl}/auth/login`;
  window.location.href = loginUrl; // Redirect to backend
}
```

**Backend Endpoint:** `GET /api/auth/login`
- **Handler:** `AuthController.login()` → `AuthManager.initiateLogin()`
- **Strategy:** `OpenIDConnectStrategy.initiateLogin()`

---

## 🔧 **2. Backend OIDC Flow Initiation**

### **Enhanced Security Parameter Generation:**
```typescript
const { randomPKCECodeVerifier, calculatePKCECodeChallenge, randomState, randomNonce } = openidClient;

// Generate security parameters
const codeVerifier = randomPKCECodeVerifier();
const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);
const state = randomState();
const nonce = randomNonce();
```

### **Session Storage (Step 1):**
```typescript
// Store OIDC parameters in user session for callback validation
(req.session as any).oidcParams = {
  codeVerifier,  // For PKCE validation
  state,         // For CSRF protection
  nonce          // For replay protection
};
```

### **Authorization URL Construction:**
```typescript
const parameters = {
  redirect_uri: 'https://node.localhost/api/auth/callback',
  scope: 'openid profile email',
  code_challenge: codeChallenge,
  code_challenge_method: 'S256',
  state,
  nonce,
  ...(process.env.OIDC_ACR_VALUES && { acr_values: process.env.OIDC_ACR_VALUES })
};
```

**Redirect:** User browser → Mock OIDC Provider (`/api/mock-oidc/auth`)

---

## 🎭 **3. Mock OIDC Provider Authentication**

### **Security Validation Interface:**
The mock OIDC shows a detailed security validation UI:

```html
✅ OIDC Security Validation Results:
- Client ID: mock-client ✅ Verified
- Redirect URI: https://node.localhost/api/auth/callback ✅ Whitelisted
- State: [random-value] ✅ CSRF Protection
- Nonce: [random-value] ✅ Replay Protection
- PKCE: Challenge with S256 ✅ Enhanced Security
- ACR Values: mfa,level2 ✅ Authentication Context
```

### **User Selection & Authorization Code Generation:**
```typescript
// User selects mock user (admin@example.com, user@example.com, etc.)
const authCode = this.generateSecureToken();

// Store authorization code with security context
this.authorizationCodes.set(authCode, {
  code: authCode,
  client_id,
  redirect_uri,
  user: mockUser,
  scope,
  nonce,           // Stored for validation
  code_challenge,  // Stored for PKCE validation
  code_challenge_method,
  expires_at: Date.now() + (10 * 60 * 1000), // 10 minutes
  used: false
});
```

**Redirect:** Mock OIDC → Backend callback (`/api/auth/callback?code=...&state=...`)

---

## 🔄 **4. Backend Callback Processing**

### **Endpoint:** `GET/POST /api/auth/callback`
- **Handler:** `AuthController.callback()` → `OpenIDConnectStrategy.handleCallback()`

### **Security Validations:**
```typescript
// 1. Retrieve stored OIDC parameters
const oidcParams = (req.session as any).oidcParams;

// 2. Exchange authorization code for tokens
const params = new URLSearchParams({
  grant_type: 'authorization_code',
  code: currentUrl.searchParams.get('code'),
  redirect_uri: callbackURL,
  client_id: this.configData.client_id,
  code_verifier: oidcParams.codeVerifier  // PKCE validation
});

// 3. Get tokens from OIDC provider
const tokenData = await fetch(tokenEndpoint, { method: 'POST', body: params });
```

### **Enhanced Security Validation:**
```typescript
// Parse ID token claims
const tokenClaims = JSON.parse(Buffer.from(idToken.split('.')[1], 'base64url'));

// Validate nonce to prevent replay attacks
if (oidcParams.nonce && tokenClaims.nonce !== oidcParams.nonce) {
  throw new Error('Invalid nonce parameter - potential replay attack detected');
}
console.log('🔒 Nonce validation passed');
```

---

## 👤 **5. User Creation/Update in Database**

### **User Provisioning:**
```typescript
// Extract user info from OIDC claims
const claims = tokens.claims();
const user = await this.createOrUpdateUser(claims);

const userInfo = {
  email: claims.email,
  firstName: claims.given_name || 'Unknown',
  lastName: claims.family_name || 'User',
  sub: claims.sub,
  oidcIssuer: 'mock-oidc',
  fullProfile: claims
};

// Database operations
if (existingUser) {
  // Update existing user
  await userRepository.update(user.id, {
    firstName, lastName,
    isActive: true,
    lastLoginAt: new Date()
  });
} else {
  // Create new user
  const user = await userRepository.create({
    email, firstName, lastName,
    role: UserRole.USER, // Default role
    isActive: true
  });
}
```

---

## 🍪 **6. Session Creation & Storage**

### **User Session Storage:**
```typescript
// Store user in Passport session
await new Promise<void>((resolve, reject) => {
  req.login(user, (err) => {
    if (err) reject(err);
    else resolve();
  });
});
```

### **Token Information Storage:**
```typescript
// Store token info for refresh capabilities
(req.session as any).tokenInfo = {
  accessToken: tokens.access_token,
  refreshToken: tokens.refresh_token,
  idToken: tokens.id_token,
  expiresAt: Date.now() + (tokens.expires_in * 1000),
  claims: claims
};
```

### **Session Cookie Configuration:**
```typescript
// Enhanced security session settings
cookie: {
  secure: true,        // HTTPS only
  httpOnly: true,      // Prevent XSS
  maxAge: 24 * 60 * 60 * 1000, // 24 hours
  sameSite: 'none',    // Cross-origin (front.localhost ↔ node.localhost)
  path: '/',
  domain: undefined    // Development setting
}
```

### **Cleanup:**
```typescript
// Clean up OIDC parameters
delete (req.session as any).oidcParams;
```

---

## 🔄 **7. Frontend Callback Handling**

### **Backend Redirect:**
```typescript
// Redirect to frontend callback route
const frontendUrl = 'https://front.localhost';
res.redirect(`${frontendUrl}/auth/callback`);
```

### **Angular Callback Component:**
```typescript
// /auth/callback route
ngOnInit(): void {
  setTimeout(() => {
    // Refresh session from backend
    this.authService.refreshSession().subscribe({
      next: (session) => {
        if (session?.isAuthenticated) {
          this.router.navigate(['/dashboard']);
        } else {
          this.router.navigate(['/auth/login']);
        }
      }
    });
  }, 1000);
}
```

---

## 🌐 **8. Frontend-Backend Communication**

### **HTTP Configuration:**
```typescript
// Global HTTP interceptor
const modifiedReq = req.clone({
  setHeaders: { 'Content-Type': 'application/json' },
  withCredentials: true  // Include session cookies
});
```

### **CORS Configuration (Backend):**
```typescript
app.use(cors({
  origin: ['https://front.localhost', 'https://node.localhost'],
  credentials: true,    // Allow cookies
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
}));
```

### **Session Endpoint:**
**Request:** `GET /api/auth/session`
```typescript
getSessionInfo(): Observable<SessionInfo | null> {
  return this.http.get<SessionInfo>(`${environment.apiUrl}/auth/session`, {
    withCredentials: true
  });
}
```

**Response Format:**
```json
{
  "user": {
    "id": "c4b8326d-5b3f-41c5-940f-012504395f01",
    "email": "user@example.com",
    "firstName": "Regular",
    "lastName": "User",
    "fullName": "Regular User",
    "role": "user",
    "isActive": true,
    "permissions": ["read"],
    "createdAt": "2025-06-26T06:32:22.694Z",
    "lastLoginAt": "2025-06-30T17:13:57.030Z"
  },
  "isAuthenticated": true
}
```

---

## 💾 **9. Frontend Session Management**

### **Angular Signals State:**
```typescript
// Reactive state management
private _currentUser = signal<User | null>(null);
private _isLoading = signal<boolean>(false);

// Computed signals
readonly isAuthenticated = computed(() => !!this._currentUser());
readonly userRole = computed(() => this._currentUser()?.role || null);
readonly userPermissions = computed(() => this._currentUser()?.permissions || []);
```

### **Session Initialization:**
```typescript
// App startup initialization
async initializeAuth(): Promise<void> {
  try {
    const sessionInfo = await this.getSessionInfo().toPromise();
    if (sessionInfo?.isAuthenticated && sessionInfo.user) {
      this._currentUser.set(sessionInfo.user);
    }
  } catch (error) {
    console.error('Auth initialization failed:', error);
  }
}
```

---

## 🛡️ **10. Route Guards & Authorization**

### **Authentication Guard:**
```typescript
export const authGuard: CanActivateFn = (route, state) => {
  const authService = inject(AuthService);

  // Initialize if needed
  if (!authService.isInitialized()) {
    return from(authService.initialize()).pipe(
      map(() => authService.isAuthenticated())
    );
  }

  // Check authentication
  if (authService.isAuthenticated()) {
    // Role-based access control
    const requiredRoles = route.data?.['roles'] as string[];
    if (requiredRoles && !authService.hasRole(requiredRoles)) {
      router.navigate(['/dashboard']);
      return false;
    }
    return true;
  }

  // Redirect to login
  router.navigate(['/auth/login'], {
    queryParams: { returnTo: state.url }
  });
  return false;
};
```

### **Role-Based Protection:**
```typescript
// Route configuration with role requirements
{
  path: 'admin',
  canActivate: [authGuard],
  data: { roles: ['admin'] },  // Only admin users
  component: AdminComponent
}
```

---

## 🔄 **11. Session Lifecycle Management**

### **Session Refresh:**
```typescript
refreshSession(): Observable<SessionInfo | null> {
  return this.getSessionInfo().pipe(
    tap(sessionInfo => {
      if (sessionInfo?.isAuthenticated && sessionInfo.user) {
        this._currentUser.set(sessionInfo.user);
      } else {
        this._currentUser.set(null);
      }
    })
  );
}
```

### **Logout Process:**
```typescript
// Frontend logout
logout(): Observable<any> {
  return this.http.post(`${environment.apiUrl}/auth/logout`, {}).pipe(
    tap(() => this._currentUser.set(null))
  );
}

// Backend logout
logout = (req: Request, res: Response): void => {
  req.logout((err) => {
    req.session.destroy((err) => {
      res.json({ message: 'Logged out successfully' });
    });
  });
};
```

### **Token Refresh (Optional):**
```typescript
// Backend token refresh endpoint
POST /api/auth/refresh-token
// Automatically refreshes OIDC tokens using refresh_token
```

---

## 🔐 **12. Security Features Summary**

### **✅ Implemented Security Measures:**

1. **PKCE (Proof Key for Code Exchange)**
   - Prevents authorization code interception attacks
   - Code verifier/challenge with SHA256

2. **State Parameter**
   - CSRF protection during OAuth flow
   - Validated on callback

3. **Nonce Parameter**
   - Replay attack prevention
   - Included in ID token and validated

4. **ACR Values**
   - Authentication Context Class Reference
   - Configurable authentication strength (mfa, level2)

5. **Secure Session Management**
   - HTTP-only cookies
   - HTTPS-only transmission
   - Cross-origin configuration
   - Rolling session expiration

6. **JWT Security**
   - RS256 signature algorithm
   - Proper claims validation
   - JWKS endpoint for verification

---

## 📊 **13. Session Data Flow Diagram**

```mermaid
graph TD
    A[User visits /dashboard] --> B[authGuard checks session]
    B --> C[GET /api/auth/session]
    C --> D{Authenticated?}
    D -->|No| E[Redirect to /auth/login]
    E --> F[AuthService.login()]
    F --> G[GET /api/auth/login]
    G --> H[OIDC flow with security params]
    H --> I[Mock OIDC authentication]
    I --> J[POST /api/auth/callback]
    J --> K[Token validation & user creation]
    K --> L[Session storage with user data]
    L --> M[Redirect to /auth/callback]
    M --> N[Angular refreshSession()]
    N --> O[GET /api/auth/session]
    O --> P[User state updated]
    P --> Q[Navigate to /dashboard]
    D -->|Yes| Q
```

---

## 🛠️ **14. API Endpoints Reference**

### **Authentication Endpoints:**
| Method | Endpoint | Purpose | Handler |
|--------|----------|---------|---------|
| GET | `/api/auth/login` | Initiate OIDC login | `AuthController.login()` |
| GET/POST | `/api/auth/callback` | Handle OIDC callback | `AuthController.callback()` |
| GET | `/api/auth/session` | Get current session info | `AuthController.getSession()` |
| POST | `/api/auth/logout` | Logout user | `AuthController.logout()` |
| POST | `/api/auth/refresh-token` | Refresh OIDC tokens | `AuthController.refreshToken()` |
| GET | `/api/auth/check` | Check auth status | `AuthController.checkAuth()` |

### **Mock OIDC Endpoints:**
| Method | Endpoint | Purpose | Handler |
|--------|----------|---------|---------|
| GET | `/api/mock-oidc/.well-known/openid-configuration` | OIDC discovery | `MockOidcController.discovery()` |
| GET | `/api/mock-oidc/auth` | Authorization endpoint | `MockOidcController.authorize()` |
| POST | `/api/mock-oidc/auth` | Handle authentication | `MockOidcController.handleAuth()` |
| POST | `/api/mock-oidc/token` | Token endpoint | `MockOidcController.token()` |
| GET | `/api/mock-oidc/userinfo` | User info endpoint | `MockOidcController.userinfo()` |
| GET | `/api/mock-oidc/.well-known/jwks.json` | JWKS endpoint | `MockOidcController.jwks()` |

---

## ⚙️ **15. Configuration Reference**

### **Environment Variables:**
```bash
# Application
NODE_ENV=development
PORT=5000

# Database
PG_HOST=postgres
PG_PORT=5432
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your-password
POSTGRES_DB=your-database

# Session Security
SESSION_SECRET=your-super-secret-session-key

# OIDC Configuration
USE_MOCK_OIDC=true
OIDC_CLIENT_ID=mock-client
OIDC_CLIENT_SECRET=mock-secret
OIDC_CALLBACK_URL=https://node.localhost/api/auth/callback
OIDC_ACR_VALUES=mfa,level2

# Frontend
FRONTEND_URL=https://front.localhost
```

### **Angular Environment:**
```typescript
export const environment = {
  production: false,
  apiUrl: 'https://node.localhost/api',
  appUrl: 'https://front.localhost'
};
```

---

## 🔍 **16. Troubleshooting Guide**

### **Common Issues:**

1. **Session Cookie Not Received:**
   - Check CORS `credentials: true`
   - Verify `withCredentials: true` in Angular requests
   - Check `sameSite: 'none'` for cross-origin

2. **OIDC Nonce Validation Fails:**
   - Ensure nonce is stored in session during login
   - Verify nonce is included in ID token
   - Check session cleanup timing

3. **PKCE Validation Fails:**
   - Verify code verifier storage in session
   - Check SHA256 challenge calculation
   - Ensure proper base64url encoding

4. **Frontend Guards Not Working:**
   - Check AuthService initialization
   - Verify session endpoint response format
   - Ensure proper signal updates

### **Debug Commands:**
```bash
# Check session endpoint
curl -b cookies.txt -X GET "https://node.localhost/api/auth/session" -k

# View backend logs
docker-compose logs node_server | tail -20

# Test OIDC discovery
curl -X GET "https://node.localhost/api/mock-oidc/.well-known/openid-configuration" -k
```

---

## 📝 **17. Migration Notes**

### **From passport-openidconnect to openid-client v6:**

1. **Dynamic Import Required:**
   ```typescript
   // Old: import { Strategy } from 'passport-openidconnect';
   // New: const openidClient = await import('openid-client');
   ```

2. **Manual Token Exchange:**
   - Old: Passport handled token exchange automatically
   - New: Manual fetch() to token endpoint with PKCE validation

3. **Enhanced Security:**
   - Added: Nonce generation and validation
   - Added: ACR values support
   - Enhanced: PKCE with proper validation

4. **Session Format Changes:**
   - Added: `createdAt` and `lastLoginAt` fields
   - Enhanced: Token storage for refresh capabilities

This comprehensive authentication system provides enterprise-grade security while maintaining excellent developer experience and user experience.
