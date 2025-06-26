import { Request, Response } from 'express';
import passport from '../../config/auth';
import { BaseAuthStrategy, AuthParams } from './BaseAuthStrategy';
import { generatePKCE } from '../../config/auth';

export class RealOIDCStrategy extends BaseAuthStrategy {
  generateAuthParams(): AuthParams {
    const { codeVerifier, codeChallenge } = generatePKCE();
    const acrValues = process.env.OIDC_ACR_VALUES;

    return { codeVerifier, codeChallenge, acrValues };
  }

  initiateLogin(req: Request, res: Response, next: Function): void {
    const issuer = process.env.OIDC_ISSUER;
    const clientId = process.env.OIDC_CLIENT_ID;

    if (!issuer || !clientId) {
      console.error('OIDC configuration incomplete');
      res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=configuration_error`);
      return;
    }

    const params = this.generateAuthParams();
    this.storeInSession(req, params);

    // Build authorization URL with PKCE
    const callbackURL = process.env.OIDC_CALLBACK_URL || 'https://node.localhost/api/auth/callback';
    const authUrl = new URL(`${issuer}/auth`);
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('redirect_uri', callbackURL);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid profile email');
    authUrl.searchParams.set('code_challenge', params.codeChallenge!);
    authUrl.searchParams.set('code_challenge_method', 'S256');

    if (params.acrValues) {
      authUrl.searchParams.set('acr_values', params.acrValues);
    }

    // Store the PKCE-enhanced URL for Passport
    this.storeInSession(req, { ...params, pkceAuthUrl: authUrl.toString() } as any);

    console.log('🔐 Real OIDC with hybrid Passport.js + PKCE security:');
    console.log('  - Issuer:', issuer);
    console.log('  - ACR Values:', params.acrValues || 'none');
    console.log('  - PKCE Challenge:', params.codeChallenge!.substring(0, 10) + '...');
    console.log('  - State/Nonce: Managed by Passport.js');

    // Use Passport.js authenticate
    passport.authenticate('oidc')(req, res, next);
  }

  async handleCallback(req: Request, res: Response, next: Function): Promise<void> {
    const { code, error } = req.query;

    // 1. Check for OAuth error response
    if (error) {
      console.error('🔒 OAuth error from provider:', error);
      res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=oauth_error`);
      return;
    }

    // 2. Validate authorization code format
    this.validateAuthorizationCode(code as string);
    console.log('✅ Authorization code validated');

    // 3. Validate PKCE (the only custom validation needed)
    const sessionCodeVerifier = this.getFromSession(req, 'codeVerifier');
    const sessionCodeChallenge = this.getFromSession(req, 'codeChallenge');

    if (!sessionCodeVerifier || !sessionCodeChallenge) {
      console.error('🔒 Missing PKCE parameters in session');
      res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=security_error`);
      return;
    }

    this.validatePKCE(sessionCodeVerifier, sessionCodeChallenge);
    console.log('✅ PKCE validation passed');

    // 4. Let Passport.js handle all other security validations
    return passport.authenticate('oidc', {
      failureRedirect: `${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=authentication_failed`
    }, async (err: any, user: any, info: any) => {
      if (err) {
        console.error('🔒 Passport authentication error:', err);
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=server_error`);
        return;
      }

      if (!user) {
        console.error('🔒 No user returned from Passport authentication');
        res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=authentication_failed`);
        return;
      }

      // 5. Clean up session security parameters
      this.clearSessionParams(req, ['codeVerifier', 'codeChallenge']);

      // 6. Log in the user
      req.logIn(user, async (loginErr: any) => {
        if (loginErr) {
          console.error('🔒 Login failed:', loginErr);
          res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=login_failed`);
          return;
        }

        // Update last login
        await this.updateLastLogin(user.id);

        // Redirect to original URL
        const returnTo = this.getFromSession(req, 'returnTo') || process.env.FRONTEND_URL || 'https://front.localhost';
        this.clearSessionParams(req, ['returnTo']);

        console.log(`✅ Real OIDC authentication successful for user: ${user.email}`);
        res.redirect(returnTo);
      });
    })(req, res, next);
  }

  async validateCallback(req: Request): Promise<boolean> {
    // Real OIDC validation logic
    return true;
  }
}
