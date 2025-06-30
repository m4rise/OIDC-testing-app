import { Request, Response } from 'express';
import { TokenInfo } from '../../middleware/security';
import { BaseAuthStrategy, AuthParams } from './BaseAuthStrategy';
import { UserRepository } from '../../repositories/UserRepository';
import { User, UserRole } from '../../entities/User';
import { UrlHelper } from '../../utils/urlHelper';
import { AuthService } from '../../services/AuthService';

export class OpenIDConnectStrategy extends BaseAuthStrategy {
  private openidClient: any;
  private config: any; // Internal config for discovery and token exchange
  private configData: any;
  private isInitialized: boolean = false;

  constructor() {
    super();
  }

  /**
   * Get the appropriate base URL for the given context
   * @param context - The communication context ('internal' for container-to-self, 'external' for browser-facing)
   */
  private getBaseUrl(context: 'internal' | 'external'): string {
    return UrlHelper.getBaseUrl(context);
  }

  /**
   * Get the appropriate OIDC issuer URL for the given context
   */
  private getOidcIssuerUrl(context: 'internal' | 'external'): string {
    return UrlHelper.getOidcIssuerUrl(context);
  }

  private getCallbackURL(): string {
    return UrlHelper.getCallbackUrl();
  }

  generateAuthParams(): AuthParams {
    // Return basic params - actual PKCE generation happens automatically in openid-client v6+
    return {
      codeVerifier: undefined,
      codeChallenge: undefined,
      nonce: undefined,
      state: undefined,
      acrValues: process.env.OIDC_ACR_VALUES
    };
  }

  async initiateLogin(req: Request, res: Response, next: Function): Promise<void> {
    if (!this.isInitialized) {
      await this.initialize();
    }

    try {
      const { randomPKCECodeVerifier, calculatePKCECodeChallenge, randomState, randomNonce, buildAuthorizationUrl } = this.openidClient;

      // Generate PKCE parameters
      const codeVerifier = randomPKCECodeVerifier();
      const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);
      const state = randomState();
      const nonce = randomNonce();

      // Store OIDC parameters in session for validation during callback
      (req.session as any).oidcParams = {
        codeVerifier,
        state,
        nonce
      };

      // Build authorization URL with enhanced security parameters
      const scope = 'openid profile email';
      const callbackURL = this.getCallbackURL();

      const parameters = {
        redirect_uri: callbackURL,
        scope,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state,
        nonce,
        // Include ACR values if configured
        ...(process.env.OIDC_ACR_VALUES && { acr_values: process.env.OIDC_ACR_VALUES })
      };

      // Use openid-client's buildAuthorizationUrl method with the discovered config
      const authorizationUrl = buildAuthorizationUrl(this.config, parameters);

      // For browser redirects, we need to ensure the URL uses the external domain
      // Replace the internal domain with the external domain if needed
      const internalDomain = UrlHelper.getOidcIssuerUrl('internal');
      const externalDomain = UrlHelper.getOidcIssuerUrl('external');

      let finalAuthUrl = authorizationUrl.href;
      if (finalAuthUrl.includes(internalDomain)) {
        finalAuthUrl = finalAuthUrl.replace(internalDomain, externalDomain);
      }

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
      const { authorizationCodeGrant, fetchUserInfo } = this.openidClient;

      // Retrieve PKCE parameters from session
      const oidcParams = (req.session as any).oidcParams;
      if (!oidcParams) {
        throw new Error('OIDC parameters not found in session');
      }

      // Get current URL for token exchange
      const currentUrl = new URL(req.originalUrl, `${req.protocol}://${req.get('host')}`);

      // Exchange authorization code for tokens with explicit redirect_uri
      const tokenEndpointUrl = new URL(this.configData.token_endpoint);
      const callbackURL = this.getCallbackURL();

      // Create the token request parameters
      const params = new URLSearchParams({
        grant_type: 'authorization_code',
        code: currentUrl.searchParams.get('code')!,
        redirect_uri: callbackURL,
        client_id: this.configData.client_id,
        code_verifier: oidcParams.codeVerifier
      });

      // Make the token request directly
      const tokenResponse = await fetch(tokenEndpointUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': `Basic ${Buffer.from(`${this.configData.client_id}:${this.configData.client_secret}`).toString('base64')}`
        },
        body: params
      });

      if (!tokenResponse.ok) {
        const errorData = await tokenResponse.text();
        throw new Error(`Token exchange failed: ${tokenResponse.status} ${errorData}`);
      }

      const tokenData = await tokenResponse.json();

      // Parse the ID token to get claims
      const idTokenParts = tokenData.id_token.split('.');
      const tokenClaims = JSON.parse(Buffer.from(idTokenParts[1], 'base64url').toString());

      // Validate nonce to prevent replay attacks
      if (oidcParams.nonce && tokenClaims.nonce !== oidcParams.nonce) {
        throw new Error('Invalid nonce parameter - potential replay attack detected');
      }

      // Create a token-like object for compatibility
      const tokens = {
        access_token: tokenData.access_token,
        refresh_token: tokenData.refresh_token,
        id_token: tokenData.id_token,
        expires_in: tokenData.expires_in,
        claims: () => tokenClaims
      };

      // Extract user info from ID token claims
      const claims = tokens.claims();

      // Create or update user in database
      const user = await this.createOrUpdateUser(claims);

      // Store user in session (using passport's req.login)
      await new Promise<void>((resolve, reject) => {
        req.login(user, (err) => {
          if (err) {
            reject(err);
          } else {
            resolve();
          }
        });
      });

      // Also store token info in session for token refresh
      (req.session as any).tokenInfo = {
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        idToken: tokens.id_token,
        expiresAt: Date.now() + (tokens.expires_in * 1000),
        claims: claims
      };

      // Clean up OIDC parameters
      delete (req.session as any).oidcParams;

      // Redirect to frontend callback route for proper session refresh
      const frontendUrl = UrlHelper.getFrontendUrl();
      res.redirect(`${frontendUrl}/auth/callback`);

    } catch (error) {
      console.error('❌ Authentication callback error:', error);

      // Clean up session
      delete (req.session as any).oidcParams;

      // Redirect to failure URL
      const failureUrl = process.env.LOGIN_FAILURE_REDIRECT_URL || '/auth/failure';
      res.redirect(failureUrl);
    }
  }

  async validateCallback(req: Request): Promise<boolean> {
    // In the new strategy, validation is handled in handleCallback
    return true;
  }

  async getUserInfo(tokenInfo: TokenInfo): Promise<any> {
    // Return the user info from the token claims
    return tokenInfo;
  }

  async initialize() {
    if (this.isInitialized) return;

    try {
      // Dynamic import for ESM modules
      this.openidClient = await import('openid-client');

      await this.setupStrategy();
      this.isInitialized = true;
    } catch (error) {
      console.error('❌ Failed to initialize OpenID Client:', error);
      throw error;
    }
  }

  private async setupStrategy() {
    const { discovery } = this.openidClient;

    if (!discovery) {
      throw new Error('Failed to import discovery from openid-client');
    }

    const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

    let serverUrl: string;
    let clientId: string;
    let clientSecret: string;

    if (useMockOIDC) {
      // For mock OIDC: use internal URL for discovery (container-to-self)
      serverUrl = this.getOidcIssuerUrl('internal');
      clientId = process.env.OIDC_CLIENT_ID || 'mock-client';
      clientSecret = process.env.OIDC_CLIENT_SECRET || 'mock-secret';
    } else {
      // Real OIDC configuration
      serverUrl = this.getOidcIssuerUrl('external');
      clientId = process.env.OIDC_CLIENT_ID!;
      clientSecret = process.env.OIDC_CLIENT_SECRET!;

      if (!serverUrl || !clientId || !clientSecret) {
        throw new Error('Missing required OIDC environment variables for real OIDC');
      }
    }

    try {
      // Create configuration using openid-client v6+ discovery
      const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

      if (useMockOIDC) {
        // For mock OIDC, allow insecure HTTP requests during discovery
        const { allowInsecureRequests } = this.openidClient;

        // Internal config for discovery and token exchange (use internal URL)
        this.config = await discovery(new URL(serverUrl), clientId, clientSecret, undefined, {
          execute: [allowInsecureRequests],
        });
      } else {
        // For real OIDC, use standard HTTPS discovery
        this.config = await discovery(new URL(serverUrl), clientId, clientSecret);
      }

      // Manually store the configuration parameters since openid-client v6
      // uses a different structure
      // IMPORTANT: Use external URLs for ALL browser-accessible endpoints
      const externalIssuerUrl = UrlHelper.getOidcIssuerUrl('external');
      const internalIssuerUrl = UrlHelper.getOidcIssuerUrl('internal');

      this.configData = {
        issuer: externalIssuerUrl, // Browser-facing issuer
        client_id: clientId,
        client_secret: clientSecret,
        token_endpoint: `${internalIssuerUrl}/token`, // Internal for server-to-server
        authorization_endpoint: `${externalIssuerUrl}/auth`, // External for browser redirects - CRITICAL!
        userinfo_endpoint: `${internalIssuerUrl}/userinfo`, // Internal for server-to-server
        jwks_uri: `${internalIssuerUrl}/.well-known/jwks.json` // Internal for server-to-server
      };

      console.log('✅ OIDC Discovery completed successfully');

    } catch (error) {
      console.error('❌ Failed to configure OIDC strategy:', error);
      throw error;
    }
  }

  /**
   * Create or update user from OIDC claims
   */
  private async createOrUpdateUser(claims: any): Promise<User> {
    const userRepository = new UserRepository();

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
      const authService = new AuthService();
      user.email = email; // Update email in case it changed
      user.firstName = firstName;
      user.lastName = lastName;
      user.role = authService.getDefaultRoleForEmail(email); // Update role based on email
      user.isActive = true;
      user.lastLoginAt = new Date();

      await userRepository.update(user.id, {
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        isActive: user.isActive,
        lastLoginAt: user.lastLoginAt
      });
    } else {
      // Create new user from OIDC data - use AuthService for proper role assignment
      const authService = new AuthService();
      const userData = {
        nni: claims.sub, // Store OIDC sub as the stable identifier
        email,
        firstName,
        lastName,
        role: authService.getDefaultRoleForEmail(email), // Use proper role assignment
        isActive: true
      };

      user = await userRepository.create(userData);
    }

    return user;
  }
}
