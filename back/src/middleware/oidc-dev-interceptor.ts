import express from 'express';
import crypto from 'crypto';
import { config as appConfig } from '../config/environment';

/**
 * OIDC Development Interceptor
 *
 * This middleware intercepts OIDC provider calls and returns mock responses
 * when DEV_BYPASS_AUTH=true in development. This allows openid-client/passport
 * to work normally while using fake OIDC responses.
 *
 * Matches the exact same API shapes, keys, and algorithms as MockOidcController
 * for perfect drop-in compatibility.
 *
 * Only activates in development with DEV_BYPASS_AUTH=true
 */

interface DevOidcConfig {
  enabled: boolean;
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  // Frontend URL for CORS and redirects
  frontendUrl: string;
  // Dev user info
  userId: string;
  userEmail: string;
  userName: string;
  userFirstName: string;
  userLastName: string;
  // JWT settings
  jwtExpiryMinutes: number;
}

function getDevOidcConfig(): DevOidcConfig {
  // Enable by default in development (unless explicitly disabled)
  const enabled = appConfig.isDevelopment && appConfig.dev.bypassAuth;

  const [firstName, ...lastNameParts] = appConfig.dev.user.name.split(' ');
  const lastName = lastNameParts.join(' ') || 'User';

  return {
    enabled,
    // Use production OIDC issuer for realistic interception
    issuer: appConfig.oidc.issuer || 'http://localhost:5000/api/mock-oidc',
    clientId: appConfig.oidc.clientId,
    clientSecret: appConfig.oidc.clientSecret,
    redirectUri: appConfig.oidc.callbackUrl,
    frontendUrl: appConfig.frontendUrl,
    // Dev user info
    userId: appConfig.dev.user.id,
    userEmail: appConfig.dev.user.email,
    userName: appConfig.dev.user.name,
    userFirstName: firstName || 'Dev',
    userLastName: lastName,
    // JWT settings
    jwtExpiryMinutes: appConfig.dev.jwt.expiryMinutes,
  };
}

// Generate the exact same RSA key pair as MockOidcController for compatibility
const MOCK_KEY_PAIR = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

const MOCK_KEY_ID = 'mock-key-1';

// Generate JWT using RS256 (same as MockOidcController)
function generateMockJWT(config: DevOidcConfig, nonce?: string, issuerOverride?: string): string {
  const header = {
    alg: 'RS256',
    typ: 'JWT',
    kid: MOCK_KEY_ID
  };

  // Use provided expiry or default to 60 minutes
  const expiryMinutes = config.jwtExpiryMinutes;
  const expiresInSeconds = expiryMinutes * 60;

  console.log(`🔐 Generating JWT with expiry: ${expiryMinutes} minutes (${expiresInSeconds} seconds)`);

  const now = Math.floor(Date.now() / 1000);
  const issuer = issuerOverride || config.issuer;

  const jwtPayload = {
    iss: issuer,
    sub: config.userId,
    aud: config.clientId,
    email: config.userEmail,
    email_verified: true,
    given_name: config.userFirstName,
    family_name: config.userLastName,
    name: config.userName,
    iat: now,
    exp: now + expiresInSeconds,
    auth_time: now,
    ...(nonce && { nonce })
  };

  const encodedHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
  const encodedPayload = Buffer.from(JSON.stringify(jwtPayload)).toString('base64url');
  const data = `${encodedHeader}.${encodedPayload}`;

  // Create signature using crypto.sign (same as MockOidcController)
  const sign = crypto.createSign('RSA-SHA256');
  sign.update(data);
  const signature = sign.sign(MOCK_KEY_PAIR.privateKey, 'base64url');

  return `${data}.${signature}`;
}

// Generate JWKS using RSA public key (same as MockOidcController)
function generateMockJWKS(): any {
  try {
    const jwk = crypto.createPublicKey(MOCK_KEY_PAIR.publicKey).export({ format: 'jwk' });

    return {
      keys: [{
        ...jwk,
        alg: 'RS256',
        use: 'sig',
        kid: MOCK_KEY_ID
      }]
    };
  } catch (error) {
    console.error('Error generating JWKS:', error);
    throw error;
  }
}

export function createOidcDevInterceptor(): express.Router {
  const devConfig = getDevOidcConfig();
  const router = express.Router();

  if (!devConfig.enabled) {
    console.log('🚫 OIDC dev interceptor disabled (DEV_BYPASS_AUTH != true)');
    return router;
  }

  console.log('🔧 OIDC dev interceptor enabled for issuer:', devConfig.issuer);
  console.log('🎭 Dev user:', devConfig.userId);

  // Parse the issuer URL to determine what paths to intercept
  const issuerUrl = new URL(devConfig.issuer);
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

    // Use the issuer from the configuration
    const baseUrl = devConfig.issuer;

    console.log('Base URL:', baseUrl);

    const discoveryDoc = {
      issuer: baseUrl,
      authorization_endpoint: `${baseUrl}/auth`,
      token_endpoint: `${baseUrl}/token`,
      userinfo_endpoint: `${baseUrl}/userinfo`,
      jwks_uri: `${baseUrl}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
      claims_supported: ['sub', 'email', 'given_name', 'family_name', 'name'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      // Test client credentials for development
      test_client_id: devConfig.clientId,
      test_client_secret: devConfig.clientSecret,
      test_basic_auth: Buffer.from(`${devConfig.clientId}:${devConfig.clientSecret}`).toString('base64')
    };

    res.json(discoveryDoc);
  });

  // JWKS endpoint (matches the path in discovery document)
  router.get(`${basePath}/.well-known/jwks.json`, (req: express.Request, res: express.Response): void => {
    logRequest(req);
    console.log('🔑 Dev interceptor: serving JWKS');
    try {
      res.json(generateMockJWKS());
    } catch (error) {
      console.error('Error generating JWKS:', error);
      res.status(500).json({ error: 'internal_server_error' });
    }
  });

  // Authorization endpoint (redirects to callback with mock code)
  router.get(`${basePath}/auth`, (req: express.Request, res: express.Response): void => {
    logRequest(req);
    console.log('🔐 Dev interceptor: authorization endpoint called');
    console.log('Query params:', req.query);

    const { redirect_uri, state, nonce, client_id, scope, response_type, code_challenge, code_challenge_method, acr_values } = req.query;

    // Enhanced validation to match MockOidcController
    if (!redirect_uri) {
      res.status(400).json({ error: 'missing_redirect_uri' });
      return;
    }

    if (!state) {
      res.status(400).json({ error: 'missing_state' });
      return;
    }

    if (!client_id || client_id !== devConfig.clientId) {
      res.status(400).json({ error: 'invalid_client_id' });
      return;
    }

    // Generate a mock authorization code
    const mockCode = 'mock-auth-code-' + crypto.randomBytes(16).toString('hex');

    // Store nonce and other parameters for token exchange (in a real scenario this would be in a database)
    (global as any).__mock_nonces = (global as any).__mock_nonces || {};
    (global as any).__mock_auth_data = (global as any).__mock_auth_data || {};

    if (nonce) {
      (global as any).__mock_nonces[mockCode] = nonce;
    }

    // Store all auth data for token exchange (matching MockOidcController behavior)
    (global as any).__mock_auth_data[mockCode] = {
      client_id,
      redirect_uri,
      scope: scope || 'openid profile email',
      nonce,
      code_challenge,
      code_challenge_method,
      acr_values
    };

    // Build enhanced callback URL with additional parameters (matching MockOidcController)
    const callbackUrl = new URL(redirect_uri as string);

    // Standard OIDC parameters
    callbackUrl.searchParams.set('code', mockCode);
    callbackUrl.searchParams.set('state', state as string);

    // Enhanced parameters - controlled by centralized config
    const includeEnhancedParams = appConfig.dev.includeEnhancedCallbackParams;

    if (includeEnhancedParams) {
      // Only add enhanced parameters if explicitly enabled (matching MockOidcController logic)
      console.log('🔧 Dev interceptor: Adding enhanced callback parameters for testing');
      callbackUrl.searchParams.set('scope', scope as string || 'openid profile email');

      // Use the issuer that matches client configuration
      const callbackIssuer = devConfig.issuer;

      callbackUrl.searchParams.set('iss', callbackIssuer);
      callbackUrl.searchParams.set('client_id', client_id as string);

      console.log('🔧 Enhanced callback issuer:', callbackIssuer);
    } else {
      console.log('🔧 Using standard OIDC callback (enhanced parameters disabled)');
    }

    console.log('🔧 Dev interceptor callback URL with parameters:', callbackUrl.toString());
    console.log('📋 Callback parameters:', {
      code: mockCode.substring(0, 8) + '...',
      state: state || 'none',
      scope: scope || 'openid profile email',
      enhanced_params: includeEnhancedParams ? 'enabled' : 'disabled'
    });

    console.log('🔄 Dev interceptor: redirecting to callback:', callbackUrl.toString());
    res.redirect(callbackUrl.toString());
  });

  // Token endpoint (enhanced to match MockOidcController)
  router.post(`${basePath}/token`, express.urlencoded({ extended: true }), (req: express.Request, res: express.Response): void => {
    logRequest(req);
    console.log('🎫 Dev interceptor: token endpoint called');
    console.log('Headers:', {
      'content-type': req.headers['content-type'],
      'authorization': req.headers.authorization ? 'Basic [REDACTED]' : 'none'
    });
    console.log('Full request body:', req.body);

    const { grant_type, code, client_id, client_secret, redirect_uri } = req.body;

    // Handle Basic Authentication (same as MockOidcController)
    let authClientId = client_id;
    let authClientSecret = client_secret;
    let authMethod = 'client_secret_post'; // Default assumption

    if (req.headers.authorization && req.headers.authorization.startsWith('Basic ')) {
      try {
        const credentials = Buffer.from(req.headers.authorization.substring(6), 'base64').toString('utf-8');
        const [basicClientId, basicClientSecret] = credentials.split(':');
        authClientId = basicClientId;
        authClientSecret = basicClientSecret;
        authMethod = 'client_secret_basic';
        console.log('🔐 DETECTED: client_secret_basic - credentials in Authorization header');
        console.log('🔐 Authorization header contains Base64 encoded clientId:clientSecret');
      } catch (error) {
        console.error('❌ Invalid Basic Authentication header');
        res.status(400).json({ error: 'invalid_client', error_description: 'Invalid Basic Authentication' });
        return;
      }
    } else if (client_id && client_secret) {
      console.log('🔐 DETECTED: client_secret_post - credentials in request body');
      console.log('🔐 Client credentials sent as form parameters');
    } else {
      console.log('❌ No client credentials found in either Authorization header or request body');
    }

    // Validate client credentials
    console.log('🔐 CLIENT AUTHENTICATION METHOD USED:', authMethod.toUpperCase());
    console.log('🔐 Validating client credentials:');
    console.log('  Expected client_id:', devConfig.clientId);
    console.log('  Expected client_secret:', devConfig.clientSecret);
    console.log('  Received client_id:', authClientId);
    console.log('  Received client_secret:', authClientSecret);

    if (authClientId !== devConfig.clientId || authClientSecret !== devConfig.clientSecret) {
      console.log('❌ Client authentication failed');
      res.status(400).json({
        error: 'invalid_client',
        error_description: 'Client authentication failed',
        details: {
          expected_client_id: devConfig.clientId,
          received_client_id: authClientId
        }
      });
      return;
    }

    if (grant_type !== 'authorization_code') {
      res.status(400).json({ error: 'unsupported_grant_type' });
      return;
    }

    if (!code || !code.startsWith('mock-auth-code-')) {
      res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid code' });
      return;
    }

    // Retrieve stored nonce and auth data for this code
    const nonce = (global as any).__mock_nonces?.[code];
    const authData = (global as any).__mock_auth_data?.[code];

    if (!authData) {
      console.error('❌ No auth data found for code');
      res.status(400).json({ error: 'invalid_grant', error_description: 'Invalid or expired code' });
      return;
    }

    console.log('🔧 Retrieved auth data:', {
      client_id: authData.client_id,
      redirect_uri: authData.redirect_uri,
      scope: authData.scope,
      nonce: nonce ? 'present' : 'missing'
    });

    // Validate redirect_uri matches the stored one (same as MockOidcController)
    if (redirect_uri !== authData.redirect_uri) {
      console.error('❌ Redirect URI mismatch');
      res.status(400).json({
        error: 'invalid_grant',
        error_description: 'Redirect URI mismatch',
        details: {
          expected: authData.redirect_uri,
          received: redirect_uri
        }
      });
      return;
    }

    // Use the environment variable issuer consistently
    const jwtIssuer = devConfig.issuer;

    console.log('🔧 JWT issuer for token:', jwtIssuer);

    // Generate enhanced ID token with all claims
    const idToken = generateMockJWT(devConfig, nonce, jwtIssuer);
    const accessToken = 'mock-access-token-' + crypto.randomBytes(16).toString('hex');
    const refreshToken = 'mock-refresh-token-' + crypto.randomBytes(16).toString('hex');

    // Clean up stored data
    if ((global as any).__mock_nonces) {
      delete (global as any).__mock_nonces[code];
    }
    if ((global as any).__mock_auth_data) {
      delete (global as any).__mock_auth_data[code];
    }

    // Token response matching MockOidcController structure
    const tokenResponse = {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: devConfig.jwtExpiryMinutes * 60, // Convert minutes to seconds using config
      id_token: idToken,
      // Include refresh_token only if offline_access scope was requested (matching MockOidcController)
      ...(authData.scope.includes('offline_access') && { refresh_token: refreshToken }),
      scope: authData.scope || 'openid profile email'
    };

    console.log('✅ Dev interceptor: returning mock tokens with issuer:', jwtIssuer);
    console.log('✅ JWT tokens generated with RS256 signature');
    res.json(tokenResponse);
  });

  // UserInfo endpoint (enhanced to match MockOidcController)
  router.get(`${basePath}/userinfo`, (req: express.Request, res: express.Response): void => {
    logRequest(req);
    console.log('👤 Dev interceptor: userinfo endpoint called');

    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({
        error: 'invalid_token',
        error_description: 'Bearer token required'
      });
      return;
    }

    const token = authHeader.substring(7);
    console.log('🎭 Userinfo request for token:', token.substring(0, 8) + '...');

    // For development, accept any bearer token and return the configured dev user
    const userInfo = {
      sub: devConfig.userId,
      email: devConfig.userEmail,
      email_verified: true,
      given_name: devConfig.userFirstName,
      family_name: devConfig.userLastName,
      name: devConfig.userName
    };

    console.log('📋 Dev interceptor: returning userinfo:', userInfo);
    res.json(userInfo);
  });

  console.log('✅ OIDC dev interceptor routes registered');
  return router;
}
