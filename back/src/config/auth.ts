import passport from 'passport';
import { Strategy as OpenIDConnectStrategy } from 'passport-openidconnect';
import { AppDataSource } from '../data-source';
import { User, UserRole } from '../entities/User';

// Configure OIDC Strategy
export const configureOIDC = () => {
  const clientID = process.env.OIDC_CLIENT_ID;
  const clientSecret = process.env.OIDC_CLIENT_SECRET;
  const issuer = process.env.OIDC_ISSUER;
  const callbackURL = process.env.OIDC_CALLBACK_URL || 'http://localhost:5000/api/auth/callback';

  if (!clientID || !clientSecret || !issuer) {
    console.warn('OIDC configuration is incomplete. Skipping OIDC strategy configuration.');
    console.warn('To enable OIDC authentication, set OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and OIDC_ISSUER environment variables.');
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
  }, async (issuer: string, profile: any, done: Function) => {
    try {
      const userRepository = AppDataSource.getRepository(User);

      // Extract subject from profile
      const sub = profile.id || profile._json?.sub || profile.sub;

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
        // Update existing OIDC user profile
        user.oidcProfile = profile._json || profile;
        user.lastLoginAt = new Date();
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
