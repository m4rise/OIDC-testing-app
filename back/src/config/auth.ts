import passport from 'passport';
import { AppDataSource } from '../data-source';
import { User, UserRole } from '../entities/User';
import { configureMockOIDC } from './mock-auth';
import { UrlHelper } from '../utils/urlHelper';

// Configure OIDC Strategy using standard openid-client/passport
export const configureOIDC = async () => {
  const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

  // Use mock OIDC in development if enabled
  if (useMockOIDC) {
    console.log('🎭 Using Mock OIDC Provider for development');
    configureMockOIDC();
  }

  if (!useMockOIDC && (!process.env.OIDC_CLIENT_ID || !process.env.OIDC_CLIENT_SECRET || !process.env.OIDC_ISSUER)) {
    console.warn('OIDC configuration is incomplete. Skipping OIDC strategy configuration.');
    console.warn('To enable OIDC authentication, set OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and OIDC_ISSUER environment variables.');
    console.warn('To use Mock OIDC for development, set USE_MOCK_OIDC=true in your .env file.');
    return;
  }

  try {
    // Import openid-client functions
    const client = await import('openid-client');
    const { Strategy } = require('openid-client/passport');

    // Get configuration - use internal URL for discovery but external for browser redirects
    const discoveryServer = new URL(useMockOIDC
      ? UrlHelper.getOidcIssuerUrl('internal')  // Use internal URL for server-to-server discovery
      : UrlHelper.getOidcIssuerUrl('external'));
    const clientId = process.env.OIDC_CLIENT_ID || 'mock-client';
    const clientSecret = process.env.OIDC_CLIENT_SECRET || 'mock-secret';
    const callbackURL = new URL(UrlHelper.getCallbackUrl());

    console.log('✅ Configuring OIDC strategy with discovery server:', discoveryServer.href);

    // Create configuration using discovery
    let config;
    if (useMockOIDC) {
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
      console.log('🔧 Authorization endpoint (external):', hybridMetadata.authorization_endpoint);
      console.log('🔧 Token endpoint (internal):', hybridMetadata.token_endpoint);
      console.log('🔧 Userinfo endpoint (internal):', hybridMetadata.userinfo_endpoint);

      // Create new configuration with hybrid endpoints
      config = new client.Configuration(hybridMetadata, clientId, clientSecret);

      // Apply allowInsecureRequests to the configuration for internal HTTP endpoints
      client.allowInsecureRequests(config);
    } else {
      config = await client.discovery(discoveryServer, clientId, clientSecret);
    }

    // Verify function following the passport.ts example
    const verify = async (tokens: any, verified: any) => {
      try {
        // Get claims from tokens
        const claims = tokens.claims();
        console.log('🔒 Processing OIDC claims:', { sub: claims.sub, email: claims.email });

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
            lastLoginAt: new Date()
          };
          user = userRepository.create(userData);
          user = await userRepository.save(user);
          console.log('🔒 Created new user from OIDC:', user.email);
        } else {
          // Update last login
          user.lastLoginAt = new Date();
          await userRepository.save(user);
          console.log('🔒 Updated existing user login:', user.email);
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

      console.log('🔐 Enhanced authorization request with mandatory parameters:', Array.from(params.entries()));
      return params;
    };

    passport.use('oidc', strategy);

    console.log('✅ OpenIDConnect strategy configured successfully');

  } catch (error) {
    console.error('❌ Failed to configure OIDC strategy:', error);
    throw error;
  }
};

// Serialize user for session - following passport.ts example
passport.serializeUser((user: any, cb) => {
  cb(null, user.id);
});

// Deserialize user from session - following passport.ts example
passport.deserializeUser(async (id: string, cb) => {
  try {
    const userRepository = AppDataSource.getRepository(User);
    const user = await userRepository.findOne({ where: { id } });
    return cb(null, user);
  } catch (error) {
    return cb(error, null);
  }
});

export default passport;
