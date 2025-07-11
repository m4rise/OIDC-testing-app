import passport from 'passport';
import { AppDataSource } from '../data-source';
import { User, UserRole } from '../entities/User';
import { configureMockOIDC } from './mock-auth';
import { UrlHelper } from '../utils/urlHelper';

// Configure OIDC Strategy using standard openid-client/passport
export const configureOIDC = async () => {
  // Default to dev interceptor in development (unless explicitly disabled)
  const useDevInterceptor = process.env.NODE_ENV === 'development' && process.env.DEV_BYPASS_AUTH !== 'false';
  const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true' && !useDevInterceptor;

  // Use legacy mock OIDC only if explicitly enabled and dev interceptor is disabled
  if (useMockOIDC) {
    console.log('🎭 Using legacy Mock OIDC Provider for development');
    configureMockOIDC();
  }

  // For dev interceptor or real OIDC, use the standard flow
  const usingMockFlow = useDevInterceptor || useMockOIDC;

  if (!usingMockFlow && (!process.env.OIDC_CLIENT_ID || !process.env.OIDC_CLIENT_SECRET || !process.env.OIDC_ISSUER)) {
    console.warn('OIDC configuration is incomplete. Skipping OIDC strategy configuration.');
    console.warn('To enable OIDC authentication, set OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and OIDC_ISSUER environment variables.');
    console.warn('For development, the Dev Interceptor is enabled by default (set DEV_BYPASS_AUTH=false to disable).');
    console.warn('For legacy mock OIDC, set USE_MOCK_OIDC=true and DEV_BYPASS_AUTH=false.');
    return;
  }

  try {
    // Import openid-client functions
    const client = await import('openid-client');
    const { Strategy } = require('openid-client/passport');

    // Get configuration - use internal URL for discovery but external for browser redirects
    const discoveryServer = new URL(usingMockFlow
      ? UrlHelper.getOidcIssuerUrl('internal')  // Use internal URL for server-to-server discovery
      : UrlHelper.getOidcIssuerUrl('external'));
    const clientId = process.env.OIDC_CLIENT_ID || 'mock-client';
    const clientSecret = process.env.OIDC_CLIENT_SECRET || 'mock-secret';
    const callbackURL = new URL(UrlHelper.getCallbackUrl());

    console.log('✅ Configuring OIDC strategy with discovery server:', discoveryServer.href);

    // Create configuration using discovery
    let config;
    if (usingMockFlow) {
      // First, discover using internal URL
      const internalConfig = await client.discovery(discoveryServer, clientId, clientSecret, undefined, {
        execute: [client.allowInsecureRequests],
      });

      // Create a hybrid configuration:
      // - Use external URL for authorization endpoint (browser redirects)
      // - Use internal URLs for token, userinfo, jwks endpoints (server-to-server)
      const internalMetadata = internalConfig.serverMetadata();
      const externalIssuer = UrlHelper.getOidcIssuerUrl('external');
      const internalIssuer = UrlHelper.getOidcIssuerUrl('internal');

      // Create server metadata with hybrid URLs
      const hybridMetadata = {
        issuer: internalIssuer, // Use internal issuer to match JWT tokens
        authorization_endpoint: `${externalIssuer}/auth`, // External - browser access
        token_endpoint: `${internalIssuer}/token`, // Internal - server-to-server
        userinfo_endpoint: `${internalIssuer}/userinfo`, // Internal - server-to-server
        jwks_uri: `${internalIssuer}/jwks`, // Internal - server-to-server
        end_session_endpoint: `${externalIssuer}/logout`, // External - browser redirect
        // Copy other important metadata from internal discovery
        response_types_supported: internalMetadata.response_types_supported,
        subject_types_supported: internalMetadata.subject_types_supported,
        id_token_signing_alg_values_supported: internalMetadata.id_token_signing_alg_values_supported,
        scopes_supported: internalMetadata.scopes_supported,
        code_challenge_methods_supported: internalMetadata.code_challenge_methods_supported,
        grant_types_supported: internalMetadata.grant_types_supported,
        response_modes_supported: internalMetadata.response_modes_supported
      };

      console.log('🔧 Creating hybrid configuration for containerized environment');

      // Create new configuration with hybrid endpoints
      config = new client.Configuration(hybridMetadata, clientId, clientSecret);

      // Apply allowInsecureRequests to the configuration for internal HTTP endpoints
      client.allowInsecureRequests(config);
    } else {
      config = await client.discovery(discoveryServer, clientId, clientSecret);
    }

    // Verify function following the passport.ts example
    // Signature is different because passReqToCallback is set to true in the Strategy options
    // This allows us to access req.session directly in the verify function
    const verify = async (req: any, tokens: any, verified: any) => {
      try {
        // Get claims from tokens
        const claims = tokens.claims();

        // Extract JWT expiry information for session management
        const jwtIat = claims.iat ? new Date(claims.iat * 1000) : new Date();
        const jwtExp = claims.exp ? new Date(claims.exp * 1000) : null;

        // Find or create user using UserRepository directly
        const userRepository = AppDataSource.getRepository(User);
        let user = await userRepository.findOne({ where: { nni: claims.sub } });

        if (!user) {
          // Create new user
          const userData = {
            nni: claims.sub, // Use OIDC sub as stable identifier
            email: claims.email,
            firstName: claims.given_name || claims.name?.split(' ')[0] || 'Unknown',
            lastName: claims.family_name || claims.name?.split(' ').slice(1).join(' ') || 'User',
            role: process.env.NODE_ENV === 'production' ? UserRole.USER :
                  (claims.email?.includes('admin') ? UserRole.ADMIN :
                   claims.email?.includes('manager') ? UserRole.MODERATOR : UserRole.USER),
            isActive: true,
            lastLoginAt: jwtIat
          };
          user = userRepository.create(userData);
          user = await userRepository.save(user);
          console.log('🔒 Created new user from OIDC:', user.email);
        } else {
          // Update last login with JWT iat timestamp
          user.lastLoginAt = jwtIat;
          await userRepository.save(user);
          console.log('🔒 Updated existing user login:', user.email);
        }

        // Store JWT expiry temporarily on user object for AuthController to access
        // This is a temporary property that won't be persisted to database
        if (jwtExp) {
          (user as any).tempJwtExpiry = jwtExp.getTime();
          console.log('🔒 Attached JWT expiry to user object:', jwtExp.toISOString());
        } else {
          console.log('🔒 JWT exp claim not found, will fallback to lastLoginAt + default lifetime');
        }

        verified(null, user);
      } catch (error) {
        console.error('❌ Error in OIDC verify function:', error);
        verified(error, null);
      }
    };

    // Strategy options following the passport.ts example
    const options = {
      config,
      scope: 'openid profile email',
      callbackURL,
      passReqToCallback: true,
    };

    // Create the strategy
    const strategy = new Strategy(options, verify);

    // Override authorizationRequestParams to always include state, nonce, and acr_values
    const originalAuthorizationRequestParams = strategy.authorizationRequestParams.bind(strategy);
    strategy.authorizationRequestParams = function(req: any, options: any) {
      const params = originalAuthorizationRequestParams(req, options) || new URLSearchParams();

      // Always add state for CSRF protection (the strategy will handle it if needed)
      if (!params.has('state')) {
        params.set('state', client.randomState());
      }

      // Always add nonce for replay protection (even for code flow)
      if (!params.has('nonce')) {
        params.set('nonce', client.randomNonce());
      }

      // Add ACR values if configured
      if (process.env.OIDC_ACR_VALUES) {
        params.set('acr_values', process.env.OIDC_ACR_VALUES);
      }

      return params;
    };

    passport.use('oidc', strategy);

    console.log('✅ OpenIDConnect strategy configured successfully');

  } catch (error) {
    console.error('❌ Failed to configure OIDC strategy:', error);
    throw error;
  }
};

// Serialize user for session
passport.serializeUser((user: any, cb) => {
  cb(null, user.id);
});

// Deserialize user from session
passport.deserializeUser(async (id: string, cb) => {
  try {
    const userRepository = AppDataSource.getRepository(User);
    const user = await userRepository.findOne({ where: { id } });
    return cb(null, user);
  } catch (error) {
    console.error('❌ Error in deserializeUser:', error);
    return cb(error, null);
  }
});

export default passport;
