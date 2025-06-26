import passport from 'passport';
import { Strategy as OpenIDConnectStrategy } from 'passport-openidconnect';
import crypto from 'crypto';
import { AppDataSource } from '../data-source';
import { User, UserRole } from '../entities/User';
import { configureMockOIDC } from './mock-auth';
import { TokenInfo } from '../middleware/security';

// PKCE and nonce generation utilities
export const generatePKCE = () => {
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
  return { codeVerifier, codeChallenge };
};

// Configure OIDC Strategy
export const configureOIDC = () => {
  const clientID = process.env.OIDC_CLIENT_ID;
  const clientSecret = process.env.OIDC_CLIENT_SECRET;
  const issuer = process.env.OIDC_ISSUER;
  const callbackURL = process.env.OIDC_CALLBACK_URL || 'https://node.localhost/api/auth/callback';
  const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

  // Use mock OIDC in development if enabled
  if (useMockOIDC) {
    console.log('🎭 Using Mock OIDC Provider for development');
    configureMockOIDC();
    return;
  }

  if (!clientID || !clientSecret || !issuer) {
    console.warn('OIDC configuration is incomplete. Skipping OIDC strategy configuration.');
    console.warn('To enable OIDC authentication, set OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and OIDC_ISSUER environment variables.');
    console.warn('To use Mock OIDC for development, set USE_MOCK_OIDC=true in your .env file.');
    return;
  }

  console.log('✅ Configuring OIDC strategy with issuer:', issuer);

  passport.use('oidc', new OpenIDConnectStrategy({
    issuer,
    authorizationURL: `${issuer}/auth`,
    tokenURL: `${issuer}/token`,
    userInfoURL: `${issuer}/userinfo`,
    clientID,
    clientSecret,
    callbackURL,
    scope: 'openid profile email',
    // Enable built-in security features
    nonce: true as any,                             // Automatic nonce generation and validation (type override needed)
    acrValues: process.env.OIDC_ACR_VALUES,        // Authentication context class reference
    passReqToCallback: true                        // Pass request to callback for additional context
  }, async (req: any, issuer: string, profile: any, done: Function) => {
    try {
      const userRepository = AppDataSource.getRepository(User);

      // Extract subject from profile
      const sub = profile.id || profile._json?.sub || profile.sub;

      // Store token information in session for token-aware session management
      // Note: passport-openidconnect may not expose actual tokens directly
      // This would need to be enhanced based on your specific OIDC provider's implementation
      console.log('⚠️  Real OIDC token extraction needs implementation');
      console.log('   passport-openidconnect may not expose tokens in this callback');
      console.log('   You may need to use a different strategy or modify the token exchange');

      // For now, create placeholder token info - this should be replaced with real token extraction
      const tokenInfo: TokenInfo = {
        accessToken: 'real_oidc_access_token_placeholder',
        idToken: 'real_oidc_id_token_placeholder',
        refreshToken: 'real_oidc_refresh_token_placeholder',
        expiresAt: Date.now() + (3600 * 1000), // 1 hour
        tokenExpiry: Date.now() + (3600 * 1000), // ID token expiry (1 hour)
        refreshExpiry: Date.now() + (30 * 24 * 60 * 60 * 1000), // 30 days
        lastRefresh: Date.now()
      };

      // TODO: Extract real tokens from OIDC provider response
      // This depends on your specific OIDC provider and how passport-openidconnect exposes tokens

      // Store token info in session
      (req.session as any).tokenInfo = tokenInfo;

      console.log('🔑 Real OIDC token placeholders stored (needs real implementation):', {
        hasAccessToken: !!tokenInfo.accessToken,
        hasIdToken: !!tokenInfo.idToken,
        hasRefreshToken: !!tokenInfo.refreshToken,
        tokenExpiresAt: new Date(tokenInfo.tokenExpiry!).toISOString(),
        refreshExpiresAt: new Date(tokenInfo.refreshExpiry!).toISOString(),
        issuer: issuer
      });

      // Try to find existing user by OIDC subject
      let user = await userRepository.findOne({
        where: { oidcSubject: sub, oidcIssuer: issuer }
      });

      if (!user) {
        // Try to find by email if user doesn't exist with OIDC
        const email = profile.emails?.[0]?.value || profile._json?.email;
        if (email) {
          user = await userRepository.findOne({ where: { email } });
        }

        if (!user) {
          // Create new user
          user = userRepository.create({
            email: email || `${sub}@${new URL(issuer).hostname}`,
            firstName: profile.name?.givenName || profile._json?.given_name || 'Unknown',
            lastName: profile.name?.familyName || profile._json?.family_name || 'User',
            oidcSubject: sub,
            oidcIssuer: issuer,
            oidcProfile: profile._json || profile,
            role: UserRole.USER,
            isActive: true,
          });
        } else {
          // Update existing user with OIDC info
          user.oidcSubject = sub;
          user.oidcIssuer = issuer;
          user.oidcProfile = profile._json || profile;
        }
      } else {
        // Update existing OIDC user profile on every login
        const previousProfile = user.oidcProfile;

        // Debug: Log what we're getting from Passport
        console.log('🔍 Passport Profile Debug:', {
          'profile.id': profile.id,
          'profile.displayName': profile.displayName,
          'profile.emails': profile.emails,
          'profile._json': profile._json,
          'profile._raw': profile._raw ? 'present' : 'missing'
        });

        user.oidcProfile = profile._json || profile;
        user.lastLoginAt = new Date();

        // Log profile changes for audit trail
        if (JSON.stringify(previousProfile) !== JSON.stringify(user.oidcProfile)) {
          console.log(`🔄 OIDC profile updated for user ${user.email}:`, {
            previous: previousProfile?.groups || [],
            current: user.oidcProfile?.groups || [],
            department: {
              from: previousProfile?.department,
              to: user.oidcProfile?.department
            }
          });
        }
      }

      await userRepository.save(user);
      return done(null, user);
    } catch (error) {
      console.error('OIDC authentication error:', error);
      return done(error, null);
    }
  }) as any);

  // Serialize user for session
  passport.serializeUser((user: any, done) => {
    done(null, user.id);
  });

  // Deserialize user from session
  passport.deserializeUser(async (id: string, done) => {
    try {
      const userRepository = AppDataSource.getRepository(User);
      const user = await userRepository.findOne({ where: { id } });
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  });
};

export default passport;
