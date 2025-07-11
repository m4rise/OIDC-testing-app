import express from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

/**
 * OIDC Development Interceptor
 *
 * This middleware intercepts OIDC provider calls and returns mock responses
 * when DEV_BYPASS_AUTH=true in development. This allows openid-client/passport
 * to work normally while using fake OIDC responses.
 *
 * Only activates in development with DEV_BYPASS_AUTH=true
 */

interface DevOidcConfig {
  enabled: boolean;
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  // Dev user info
  userId: string;
  userEmail: string;
  userName: string;
  userRoles: string[];
  // JWT settings
  jwtExpiryMinutes: number;
}

function getDevOidcConfig(): DevOidcConfig {
  // Enable by default in development (unless explicitly disabled)
  const enabled = process.env.NODE_ENV === 'development' && process.env.DEV_BYPASS_AUTH !== 'false';

  return {
    enabled,
    // Use the same issuer as the mock OIDC server to intercept those requests
    issuer: process.env.MOCK_OIDC_ISSUER || 'https://node.localhost/api/mock-oidc',
    clientId: process.env.OIDC_CLIENT_ID || 'mock-client',
    clientSecret: process.env.OIDC_CLIENT_SECRET || 'mock-secret',
    redirectUri: process.env.OIDC_REDIRECT_URI || 'https://node.localhost/api/auth/callback',
    // Dev user info
    userId: process.env.DEV_USER_ID || 'dev-user-123',
    userEmail: process.env.DEV_USER_EMAIL || 'dev.user@example.com',
    userName: process.env.DEV_USER_NAME || 'Dev User',
    userRoles: (process.env.DEV_USER_ROLES || 'user,admin').split(','),
    // JWT settings
    jwtExpiryMinutes: parseInt(process.env.DEV_JWT_EXPIRY_MINUTES || '60'),
  };
}

// Generate a mock JWT signing key
const MOCK_JWT_SECRET = 'mock-jwt-secret-for-dev-only';
const MOCK_KEY_ID = 'mock-key-1';

function generateMockJWT(config: DevOidcConfig, nonce?: string, issuerOverride?: string): string {
  const now = Math.floor(Date.now() / 1000);
  const exp = now + (config.jwtExpiryMinutes * 60);

  // Use the override issuer if provided, otherwise use the config issuer
  const issuer = issuerOverride || config.issuer;

  const payload = {
    iss: issuer,
    sub: config.userId,
    aud: config.clientId,
    exp,
    iat: now,
    auth_time: now,
    ...(nonce && { nonce }),
    email: config.userEmail,
    name: config.userName,
    preferred_username: config.userName,
    roles: config.userRoles,
  };

  return jwt.sign(payload, MOCK_JWT_SECRET, {
    algorithm: 'HS256',
    keyid: MOCK_KEY_ID,
  });
}

function generateMockJWKS(): any {
  // Generate a mock JWKS for the fake signing key
  return {
    keys: [
      {
        kty: 'oct',
        kid: MOCK_KEY_ID,
        use: 'sig',
        alg: 'HS256',
        k: Buffer.from(MOCK_JWT_SECRET).toString('base64url'),
      }
    ]
  };
}

export function createOidcDevInterceptor(): express.Router {
  const config = getDevOidcConfig();
  const router = express.Router();

  if (!config.enabled) {
    console.log('🚫 OIDC dev interceptor disabled (DEV_BYPASS_AUTH != true)');
    return router;
  }

  console.log('🔧 OIDC dev interceptor enabled for issuer:', config.issuer);
  console.log('🎭 Dev user:', config.userEmail, 'with roles:', config.userRoles.join(','));

  // Parse the issuer URL to determine what paths to intercept
  const issuerUrl = new URL(config.issuer);
  const basePath = issuerUrl.pathname === '/' ? '' : issuerUrl.pathname;

  console.log('🛤️ Dev interceptor will intercept paths starting with:', basePath);

  // Add specific route loggers instead of catch-all to avoid path-to-regexp issues
  const logRequest = (req: express.Request) => {
    console.log(`🔍 Dev interceptor: ${req.method} ${req.path} (full URL: ${req.originalUrl})`);
    console.log('Query params:', req.query);
    console.log('Headers:', { host: req.get('host'), origin: req.get('origin'), 'user-agent': req.get('user-agent') });
  };

  // OIDC Discovery Document
  router.get(`${basePath}/.well-known/openid-configuration`, (req: express.Request, res: express.Response): void => {
    logRequest(req);
    console.log('🔍 Dev interceptor: serving OIDC discovery document');

    // Determine the issuer based on the request (internal vs external)
    const isInternalRequest = req.get('host')?.includes('localhost:5000') || req.get('host')?.includes('127.0.0.1');
    const issuerUrl = isInternalRequest
      ? `http://localhost:5000${basePath}`
      : config.issuer;

    const discoveryDoc = {
      issuer: issuerUrl,
      authorization_endpoint: `${config.issuer}/auth`,
      token_endpoint: `${issuerUrl}/token`,
      userinfo_endpoint: `${issuerUrl}/userinfo`,
      jwks_uri: `${issuerUrl}/jwks`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['HS256'],
      scopes_supported: ['openid', 'profile', 'email'],
      claims_supported: ['sub', 'name', 'email', 'preferred_username', 'roles'],
      grant_types_supported: ['authorization_code'],
      code_challenge_methods_supported: ['S256', 'plain'],
    };

    res.json(discoveryDoc);
  });

  // JWKS endpoint
  router.get(`${basePath}/jwks`, (req: express.Request, res: express.Response): void => {
    logRequest(req);
    console.log('🔑 Dev interceptor: serving JWKS');
    res.json(generateMockJWKS());
  });

  // Authorization endpoint (redirects to callback with mock code)
  router.get(`${basePath}/auth`, (req: express.Request, res: express.Response): void => {
    logRequest(req);
    console.log('🔐 Dev interceptor: authorization endpoint called');
    console.log('Query params:', req.query);

    const { redirect_uri, state, nonce, client_id } = req.query;

    if (!redirect_uri || !state) {
      res.status(400).json({ error: 'missing_parameters' });
      return;
    }

    // Generate a mock authorization code
    const mockCode = 'mock-auth-code-' + crypto.randomBytes(16).toString('hex');

    // Store nonce for token exchange (in a real scenario this would be in a database)
    if (nonce) {
      (global as any).__mock_nonces = (global as any).__mock_nonces || {};
      (global as any).__mock_nonces[mockCode] = nonce;
    }

    // Redirect back to the callback with mock code
    const callbackUrl = new URL(redirect_uri as string);
    callbackUrl.searchParams.set('code', mockCode);
    callbackUrl.searchParams.set('state', state as string);

    console.log('🔄 Dev interceptor: redirecting to callback:', callbackUrl.toString());
    res.redirect(callbackUrl.toString());
  });

  // Token endpoint
  router.post(`${basePath}/token`, express.urlencoded({ extended: true }), (req: express.Request, res: express.Response): void => {
    logRequest(req);
    console.log('🎫 Dev interceptor: token endpoint called');
    console.log('Body:', req.body);

    const { grant_type, code, client_id, client_secret, redirect_uri } = req.body;

    if (grant_type !== 'authorization_code') {
      res.status(400).json({ error: 'unsupported_grant_type' });
      return;
    }

    if (!code || !code.startsWith('mock-auth-code-')) {
      res.status(400).json({ error: 'invalid_grant' });
      return;
    }

    // Retrieve stored nonce for this code
    const nonce = (global as any).__mock_nonces?.[code];

    // Determine the correct issuer for the JWT (should match the discovery document issuer)
    const isInternalRequest = req.get('host')?.includes('localhost:5000') || req.get('host')?.includes('127.0.0.1');
    const jwtIssuer = isInternalRequest
      ? `http://localhost:5000${basePath}`
      : config.issuer;

    // Generate mock tokens with the correct issuer
    const idToken = generateMockJWT(config, nonce, jwtIssuer);
    const accessToken = 'mock-access-token-' + crypto.randomBytes(16).toString('hex');

    // Clean up stored nonce
    if ((global as any).__mock_nonces) {
      delete (global as any).__mock_nonces[code];
    }

    const tokenResponse = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: config.jwtExpiryMinutes * 60,
      id_token: idToken,
      scope: 'openid profile email',
    };

    console.log('✅ Dev interceptor: returning mock tokens with issuer:', jwtIssuer);
    res.json(tokenResponse);
  });

  // UserInfo endpoint
  router.get(`${basePath}/userinfo`, (req: express.Request, res: express.Response): void => {
    logRequest(req);
    console.log('👤 Dev interceptor: userinfo endpoint called');

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ error: 'invalid_token' });
      return;
    }

    const userInfo = {
      sub: config.userId,
      email: config.userEmail,
      name: config.userName,
      preferred_username: config.userName,
      roles: config.userRoles,
    };

    console.log('📋 Dev interceptor: returning userinfo:', userInfo);
    res.json(userInfo);
  });

  console.log('✅ OIDC dev interceptor routes registered');
  return router;
}
