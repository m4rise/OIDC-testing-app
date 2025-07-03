import { Request, Response } from 'express';
import { TokenInfo } from '../../middleware/security';
import { BaseAuthStrategy } from './BaseAuthStrategy';
import { UserRepository } from '../../repositories/UserRepository';
import { User } from '../../entities/User';
import { UrlHelper } from '../../utils/urlHelper';
import { AuthService } from '../../services/AuthService';

export class OpenIDConnectStrategy extends BaseAuthStrategy {
  private client: any;
  private isInitialized: boolean = false;

  constructor() {
    super();
  }

  async initiateLogin(req: Request, res: Response, next: Function): Promise<void> {
    if (!this.isInitialized) {
      await this.initialize();
    }

    try {
      const scope = 'openid profile email';
      const callbackURL = UrlHelper.getCallbackUrl();

      // Use openid-client v6+ buildAuthorizationUrl with proper security parameters
      const { buildAuthorizationUrl, randomState, randomNonce, randomPKCECodeVerifier, calculatePKCECodeChallenge } = await import('openid-client');

      // Generate security parameters
      const state = randomState();
      const nonce = randomNonce();
      const codeVerifier = randomPKCECodeVerifier();
      const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);

      // Build authorization URL with proper security parameters
      const authorizationUrl = buildAuthorizationUrl(this.client, {
        scope,
        redirect_uri: callbackURL,
        state,
        nonce,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        ...(process.env.OIDC_ACR_VALUES && { acr_values: process.env.OIDC_ACR_VALUES })
      });

      // Store security parameters in session for validation during callback
      (req.session as any).oidcState = state;
      (req.session as any).oidcNonce = nonce;
      (req.session as any).oidcCodeVerifier = codeVerifier;

      // Patch authorization URL to use external domain for browser redirects
      const internalDomain = UrlHelper.getOidcIssuerUrl('internal');
      const externalDomain = UrlHelper.getOidcIssuerUrl('external');

      let finalAuthUrl = authorizationUrl.href;
      if (finalAuthUrl.includes(internalDomain)) {
        finalAuthUrl = finalAuthUrl.replace(internalDomain, externalDomain);
      }

      console.log('🔐 Authorization URL with security params:', finalAuthUrl);
      res.redirect(finalAuthUrl);

    } catch (error) {
      console.error('❌ Error initiating login:', error);
      const failureUrl = process.env.LOGIN_FAILURE_REDIRECT_URL || '/auth/failure';
      res.redirect(failureUrl);
    }
  }

  async handleCallback(req: Request, res: Response, next: Function): Promise<void> {
    if (!this.isInitialized) {
      await this.initialize();
    }

    try {
      const currentUrl = new URL(req.originalUrl, `${req.protocol}://${req.get('host')}`);
      console.log('🔄 Handling OIDC callback at:', currentUrl.href);

      // Retrieve stored security parameters from session
      const storedState = (req.session as any).oidcState;
      const storedNonce = (req.session as any).oidcNonce;
      const storedCodeVerifier = (req.session as any).oidcCodeVerifier;

      // Use openid-client v6+ built-in methods
      const { authorizationCodeGrant, fetchUserInfo } = await import('openid-client');

      // Exchange authorization code for tokens with PKCE validation
      const tokenSet = await authorizationCodeGrant(this.client, currentUrl, {
        pkceCodeVerifier: storedCodeVerifier,
        expectedNonce: storedNonce,
        expectedState: storedState
      });

      // Parse ID token claims first to get the subject
      let idTokenClaims: any = {};
      if (tokenSet.id_token) {
        const idTokenParts = tokenSet.id_token.split('.');
        if (idTokenParts[1]) {
          idTokenClaims = JSON.parse(Buffer.from(idTokenParts[1], 'base64').toString());
        }
      }

      // Validate nonce if present
      if (storedNonce && idTokenClaims.nonce !== storedNonce) {
        throw new Error('Nonce validation failed');
      }

      // Get user info using the access token and expected subject from ID token
      const userinfo = await fetchUserInfo(this.client, tokenSet.access_token, idTokenClaims.sub);

      // Merge ID token claims with userinfo
      const claims = { ...idTokenClaims, ...userinfo };

      // Create or update user in database
      const user = await this.createOrUpdateUser(claims);

      // Store user in session using passport
      await new Promise<void>((resolve, reject) => {
        req.login(user, (err) => {
          if (err) {
            reject(err);
          } else {
            resolve();
          }
        });
      });

      // Store token info in session
      (req.session as any).tokenInfo = {
        accessToken: tokenSet.access_token,
        refreshToken: tokenSet.refresh_token,
        idToken: tokenSet.id_token,
        expiresAt: tokenSet.expires_in ? Date.now() + (tokenSet.expires_in * 1000) : Date.now() + 3600000,
        claims: claims
      };

      // Clean up temporary session data
      delete (req.session as any).oidcState;
      delete (req.session as any).oidcNonce;
      delete (req.session as any).oidcCodeVerifier;

      // Redirect to frontend
      const frontendUrl = UrlHelper.getFrontendUrl();
      res.redirect(`${frontendUrl}/auth/callback`);

    } catch (error) {
      console.error('❌ Authentication callback error:', error);

      // Clean up session
      delete (req.session as any).oidcState;
      delete (req.session as any).oidcNonce;
      delete (req.session as any).oidcCodeVerifier;
      const failureUrl = process.env.LOGIN_FAILURE_REDIRECT_URL || '/auth/failure';
      res.redirect(failureUrl);
    }
  }

  async initialize() {
    if (this.isInitialized) return;

    try {
      // openid-client v6+ uses functional approach, setup is done in setupClient
      await this.setupClient();
      this.isInitialized = true;
    } catch (error) {
      console.error('❌ Failed to initialize OpenID Client:', error);
      throw error;
    }
  }

  private async setupClient() {
    const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

    let issuerUrl: string;
    let clientId: string;
    let clientSecret: string;

    if (useMockOIDC) {
      // For mock OIDC: use internal URL for server-to-server communication
      issuerUrl = UrlHelper.getOidcIssuerUrl('internal');
      clientId = process.env.OIDC_CLIENT_ID || 'mock-client';
      clientSecret = process.env.OIDC_CLIENT_SECRET || 'mock-secret';
    } else {
      // Real OIDC configuration
      issuerUrl = UrlHelper.getOidcIssuerUrl('external');
      clientId = process.env.OIDC_CLIENT_ID!;
      clientSecret = process.env.OIDC_CLIENT_SECRET!;

      if (!issuerUrl || !clientId || !clientSecret) {
        throw new Error('Missing required OIDC environment variables');
      }
    }

    try {
      // Use openid-client v6+ discovery pattern
      const { discovery, allowInsecureRequests } = await import('openid-client');

      // For mock OIDC, configure to allow insecure requests
      if (useMockOIDC) {
        this.client = await discovery(new URL(issuerUrl), clientId, clientSecret, undefined, {
          execute: [allowInsecureRequests],
        });
      } else {
        this.client = await discovery(new URL(issuerUrl), clientId, clientSecret);
      }

      console.log('✅ OIDC Discovery completed successfully');

    } catch (error) {
      console.error('❌ Failed to configure OIDC client:', error);
      throw error;
    }
  }

  /**
   * Create or update user from OIDC claims
   */
  private async createOrUpdateUser(claims: any): Promise<User> {
    const userRepository = new UserRepository();
    const authService = new AuthService();

    // Extract user info from claims
    const email = claims.email;
    const name = claims.name || claims.preferred_username || email;
    const nameParts = name.split(' ');
    const firstName = claims.given_name || nameParts[0] || 'Unknown';
    const lastName = claims.family_name || nameParts.slice(1).join(' ') || 'User';

    // Try to find existing user by sub (stored in nni field)
    let user = await userRepository.findByNni(claims.sub);

    if (user) {
      // Update existing user with latest OIDC data and role
      const expectedRole = authService.getDefaultRoleForEmail(email);
      await userRepository.update(user.id, {
        email,
        firstName,
        lastName,
        role: expectedRole,
        isActive: true,
        lastLoginAt: new Date()
      });
      user = await userRepository.findById(user.id) || user;
    } else {
      // Create new user from OIDC data
      const userData = {
        nni: claims.sub,
        email,
        firstName,
        lastName,
        role: authService.getDefaultRoleForEmail(email),
        isActive: true,
        lastLoginAt: new Date()
      };

      user = await userRepository.create(userData);
      console.log(`✅ Created new user from OIDC: ${user.email} (nni: ${user.nni}) with role: ${user.role}`);
    }

    return user;
  }
}
