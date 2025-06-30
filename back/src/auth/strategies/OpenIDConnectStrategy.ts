import { Request, Response } from 'express';
import passport from 'passport';
import { AuthService } from '../../services/AuthService';
import { TokenInfo } from '../../middleware/security';
import { BaseAuthStrategy, AuthParams } from './BaseAuthStrategy';

export class OpenIDConnectStrategy extends BaseAuthStrategy {
  private openidClient: any;
  private config: any;
  private configData: any;
  private isInitialized: boolean = false;

  constructor() {
    super();
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
      const { randomPKCECodeVerifier, calculatePKCECodeChallenge, randomState, buildAuthorizationUrl } = this.openidClient;

      // Generate PKCE parameters
      const codeVerifier = randomPKCECodeVerifier();
      const codeChallenge = await calculatePKCECodeChallenge(codeVerifier);
      const state = randomState();

      // Store PKCE parameters in session
      (req.session as any).oidcParams = {
        codeVerifier,
        state
      };

      // Build authorization URL
      const scope = 'openid profile email';
      const callbackURL = this.getCallbackURL();

      const parameters = {
        redirect_uri: callbackURL,
        scope,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        state
      };

      const authorizationUrl = buildAuthorizationUrl(this.config, parameters);

      console.log('🔗 Redirecting to authorization URL:', authorizationUrl.href);
      res.redirect(authorizationUrl.href);

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
      console.log('🔧 Config:', this.config);
      console.log('🔧 Using manual config data for token exchange');
      const tokenEndpointUrl = new URL(this.configData.token_endpoint);
      const callbackURL = this.getCallbackURL();

      console.log('🔧 Token endpoint:', tokenEndpointUrl.href);
      console.log('🔧 Callback URL:', callbackURL);

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

      console.log('✅ Tokens received successfully');

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
      const userInfo = {
        sub: claims.sub,
        email: claims.email,
        name: claims.name,
        preferred_username: claims.preferred_username
      };

      // Store user and tokens in session
      (req.session as any).user = {
        ...userInfo,
        tokenInfo: {
          accessToken: tokens.access_token,
          refreshToken: tokens.refresh_token,
          idToken: tokens.id_token,
          expiresAt: Date.now() + (tokens.expires_in * 1000),
          claims: claims
        }
      };

      // Clean up OIDC parameters
      delete (req.session as any).oidcParams;

      console.log('✅ User authenticated and stored in session:', userInfo.sub);

      // Redirect to success URL
      const successUrl = process.env.LOGIN_SUCCESS_REDIRECT_URL || '/auth/success';
      res.redirect(successUrl);

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

  private getCallbackURL(): string {
    // Always use the callback URL from environment
    return process.env.OIDC_CALLBACK_URL || 'https://node.localhost/api/auth/callback';
  }

  async initialize() {
    if (this.isInitialized) return;

    try {
      // Dynamic import for ESM modules
      this.openidClient = await import('openid-client');

      console.log('✅ OpenID Client v6+ loaded successfully');

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

    console.log('✅ Successfully imported discovery from openid-client');

    const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

    let serverUrl: string;
    let clientId: string;
    let clientSecret: string;

    if (useMockOIDC) {
      console.log('🔧 Using Mock OIDC configuration');

      // For mock OIDC: use internal HTTP for discovery (container-to-container)
      // but external HTTPS for redirects (browser-to-traefik)
      serverUrl = 'http://localhost:5000/api/mock-oidc'; // Internal discovery
      clientId = process.env.OIDC_CLIENT_ID || 'mock-client';
      clientSecret = process.env.OIDC_CLIENT_SECRET || 'mock-secret';
    } else {
      console.log('🔧 Using Real OIDC configuration');

      // Real OIDC configuration
      serverUrl = process.env.OIDC_ISSUER!;
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
        console.log('🔧 Configuring discovery with HTTP support for mock OIDC');

        this.config = await discovery(new URL(serverUrl), clientId, clientSecret, undefined, {
          execute: [allowInsecureRequests],
        });
      } else {
        // For real OIDC, use standard HTTPS discovery
        this.config = await discovery(new URL(serverUrl), clientId, clientSecret);
      }

      // Manually store the configuration parameters since openid-client v6
      // uses a different structure
      this.configData = {
        issuer: serverUrl,
        client_id: clientId,
        client_secret: clientSecret,
        token_endpoint: `${serverUrl}/token`,
        authorization_endpoint: `${serverUrl}/auth`,
        userinfo_endpoint: `${serverUrl}/userinfo`,
        jwks_uri: `${serverUrl}/.well-known/jwks.json`
      };

      console.log('✅ OIDC Discovery completed successfully');
      console.log('🔧 Manual config data:', this.configData);
      console.log(`📍 Server URL: ${serverUrl}`);
      console.log(`📍 Client ID: ${clientId}`);
      console.log(`📍 Callback URL: ${this.getCallbackURL()}`);

    } catch (error) {
      console.error('❌ Failed to configure OIDC strategy:', error);
      throw error;
    }
  }
}
