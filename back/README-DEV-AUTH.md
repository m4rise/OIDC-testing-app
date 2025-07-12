# Development Authentication Setup

This project includes a robust OIDC development interceptor that allows you to bypass real OIDC providers during development while keeping all the Passport.js, session, and database logic intact.

## Quick Start

### Enable Development Bypass

**The dev interceptor is enabled by default in development!**

1. For most development work, no configuration needed:
```bash
NODE_ENV=development
# DEV_BYPASS_AUTH=true (default, can be omitted)
```

2. Configure your test user (optional, defaults provided):
```bash
DEV_USER_ID=dev-user-123
DEV_USER_EMAIL=dev.user@example.com
DEV_USER_NAME=Dev User
DEV_USER_ROLES=user,admin
DEV_JWT_EXPIRY_MINUTES=60
```

3. To disable the dev interceptor (not recommended):
```bash
DEV_BYPASS_AUTH=false
```

**Note**: The dev interceptor works by intercepting requests to `/api/mock-oidc/*` and returning mock responses inline. It's simpler, more reliable, and easier to debug than any external mock servers.

## How It Works

The OIDC Development Interceptor (`src/middleware/oidc-dev-interceptor.ts`) intercepts HTTP requests that would normally go to your real OIDC provider and returns mock responses instead.

### What Gets Intercepted

When `DEV_BYPASS_AUTH=true` and `NODE_ENV=development`:

- **Discovery Document** (`/.well-known/openid-configuration`)
- **JWKS Endpoint** (`/jwks`)
- **Authorization Endpoint** (`/auth`)
- **Token Endpoint** (`/token`)
- **UserInfo Endpoint** (`/userinfo`)

### What Stays The Same

- ✅ Passport.js authentication flow
- ✅ Session management and database storage
- ✅ User entity creation and updates
- ✅ JWT token validation and expiry
- ✅ All your authentication middleware
- ✅ Role-based access control

## Development Flow

1. **Frontend initiates login** → same as production
2. **Backend redirects to OIDC** → intercepted by dev middleware
3. **Mock authorization** → returns fake auth code
4. **Token exchange** → returns mock JWT with configurable user data
5. **User session created** → real database session with mock user
6. **Authentication complete** → normal app flow continues

## Environment Variables

### Required for Dev Bypass
- `DEV_BYPASS_AUTH=true` - Enables the interceptor (only works in development)
- `NODE_ENV=development` - Required for security

### OIDC Configuration
- `OIDC_ISSUER` - The issuer URL to intercept (matches your production issuer)
- `OIDC_CLIENT_ID` - Client ID (can be mock value for dev)
- `OIDC_CLIENT_SECRET` - Client secret (can be mock value for dev)
- `OIDC_REDIRECT_URI` - Callback URL

### Test User Configuration
- `DEV_USER_ID` - User ID for the mock user (default: `dev-user-123`)
- `DEV_USER_EMAIL` - Email for the mock user (default: `dev.user@example.com`)
- `DEV_USER_NAME` - Display name (default: `Dev User`)
- `DEV_USER_ROLES` - Comma-separated roles (default: `user,admin`)

### JWT Configuration
- `DEV_JWT_EXPIRY_MINUTES` - JWT expiry time in minutes (default: `60`)
- `SESSION_ROLLING_MINUTES` - Session rolling expiry (default: `10`)

## Security Features

- **Environment Lock**: Only works when `NODE_ENV=development`
- **Explicit Enable**: Requires `DEV_BYPASS_AUTH=true`
- **No Production Impact**: Completely disabled in production
- **Same Auth Logic**: Uses real Passport.js and session logic

## Switching Between Dev and Production

### Development Mode (Default)
```bash
NODE_ENV=development
# DEV_BYPASS_AUTH=true (default in development)
```

### Production Mode
```bash
NODE_ENV=production
# DEV_BYPASS_AUTH automatically disabled
OIDC_ISSUER=https://your-real-oidc-provider.com
OIDC_CLIENT_ID=your-real-client-id
OIDC_CLIENT_SECRET=your-real-client-secret
```

## Testing Different Users

You can quickly test different user scenarios by changing the environment variables:

```bash
# Test as admin user
DEV_USER_ROLES=admin,superuser
DEV_USER_EMAIL=admin@example.com

# Test as regular user
DEV_USER_ROLES=user
DEV_USER_EMAIL=user@example.com

# Test with short JWT expiry
DEV_JWT_EXPIRY_MINUTES=1
```

Then restart your development server to apply the changes.

## Troubleshooting

### Interceptor Not Working
- Check that `DEV_BYPASS_AUTH=true` is set
- Verify `NODE_ENV=development`
- Look for "🔧 OIDC dev interceptor enabled" in server logs

### TypeScript Errors
- Ensure `jsonwebtoken` and `@types/jsonwebtoken` are installed
- Run: `docker-compose exec node_server pnpm install`

### Session Issues
- Check database connection
- Verify `SESSION_SECRET` is set
- Check session table in PostgreSQL

## Architecture

```
Frontend Login Request
         ↓
Express App (app.ts)
         ↓
OIDC Dev Interceptor (if DEV_BYPASS_AUTH=true)
         ↓ (intercepts)
Mock OIDC Responses
         ↓
Passport.js OIDC Strategy
         ↓
Session Creation (Real DB)
         ↓
Authentication Complete
```

This approach gives you the best of both worlds: fast development iteration with production-like authentication behavior.
