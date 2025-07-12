import passport from 'passport';
import { AppDataSource } from '../data-source';
import { User, UserRole } from '../entities/User';
import { config as appConfig } from './environment';

// Configure OIDC Strategy using standard openid-client/passport
export const configureOIDC = async () => {
  // Default to dev interceptor in development (unless explicitly disabled)
  const useDevInterceptor = appConfig.isDevelopment && appConfig.dev.bypassAuth;

  if (!useDevInterceptor && (!appConfig.oidc.clientId || !appConfig.oidc.clientSecret || !appConfig.oidc.issuer)) {
    console.warn('OIDC configuration is incomplete. Skipping OIDC strategy configuration.');
    console.warn('To enable OIDC authentication, set OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and OIDC_ISSUER environment variables.');
    console.warn('For development, the Dev Interceptor is enabled by default (set DEV_BYPASS_AUTH=false to disable).');
    return;
  }

  try {
    // Import openid-client functions
    const client = await import('openid-client');
    const { Strategy } = require('openid-client/passport');

    // Get configuration
    const issuerUrl = useDevInterceptor
      ? appConfig.dev.oidcIssuer  // Dev interceptor URL
      : appConfig.oidc.issuer!;   // Real OIDC provider URL (validated above)

    const clientId = appConfig.oidc.clientId;
    const clientSecret = appConfig.oidc.clientSecret;
    const callbackURL = appConfig.oidc.callbackUrl;

    console.log('✅ Configuring OIDC strategy with issuer:', issuerUrl);
    console.log('✅ Callback URL:', callbackURL);

    // Create configuration using discovery
    const config = await client.discovery(new URL(issuerUrl), clientId, clientSecret, undefined, {
      execute: useDevInterceptor ? [client.allowInsecureRequests] : undefined,
    });

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
            role: appConfig.isProduction ? UserRole.USER :
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
      if (appConfig.oidc.acrValues) {
        params.set('acr_values', appConfig.oidc.acrValues);
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
