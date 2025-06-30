import passport from 'passport';
import { AppDataSource } from '../data-source';
import { User } from '../entities/User';
import { configureMockOIDC } from './mock-auth';
import { OpenIDConnectStrategy } from '../auth/strategies/OpenIDConnectStrategy';

// Configure OIDC Strategy
export const configureOIDC = async () => {
  const clientID = process.env.OIDC_CLIENT_ID;
  const clientSecret = process.env.OIDC_CLIENT_SECRET;
  const issuer = process.env.OIDC_ISSUER;
  const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

  // Use mock OIDC in development if enabled
  if (useMockOIDC) {
    console.log('🎭 Using Mock OIDC Provider for development with openid-client');
    // Still configure mock OIDC routes for the backend
    configureMockOIDC();
  }

  if (!useMockOIDC && (!clientID || !clientSecret || !issuer)) {
    console.warn('OIDC configuration is incomplete. Skipping OIDC strategy configuration.');
    console.warn('To enable OIDC authentication, set OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and OIDC_ISSUER environment variables.');
    console.warn('To use Mock OIDC for development, set USE_MOCK_OIDC=true in your .env file.');
    return;
  }

  const issuerToUse = useMockOIDC
    ? 'https://node.localhost/api/mock-oidc'
    : issuer;

  console.log('✅ Configuring OIDC strategy with issuer:', issuerToUse);

  // Initialize the OpenIDConnect strategy (this will register the passport strategy internally)
  const oidcStrategy = new OpenIDConnectStrategy();
  await oidcStrategy.initialize();

  console.log('✅ OpenIDConnect strategy initialized successfully');

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
