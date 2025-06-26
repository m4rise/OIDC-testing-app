import { Request, Response } from 'express';
import { AuthStrategy } from './strategies/BaseAuthStrategy';
import { MockOIDCStrategy } from './strategies/MockOIDCStrategy';
import { RealOIDCStrategy } from './strategies/RealOIDCStrategy';

export class AuthManager {
  private strategy: AuthStrategy;

  constructor() {
    this.strategy = this.createStrategy();
  }

  private createStrategy(): AuthStrategy {
    const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

    if (useMockOIDC) {
      console.log('🎭 Using Mock OIDC Strategy');
      return new MockOIDCStrategy();
    } else {
      console.log('🔐 Using Real OIDC Strategy');
      return new RealOIDCStrategy();
    }
  }

  async initiateLogin(req: Request, res: Response, next: Function): Promise<void> {
    // Store returnTo URL
    const returnTo = req.query.returnTo as string || '/';
    console.log('🎭 Storing returnTo in session:', returnTo);

    if (req.session) {
      (req.session as any).returnTo = returnTo;
      console.log('🎭 Session ID when storing returnTo:', req.sessionID);
    }

    return this.strategy.initiateLogin(req, res, next);
  }

  async handleCallback(req: Request, res: Response, next: Function): Promise<void> {
    try {
      return await this.strategy.handleCallback(req, res, next);
    } catch (error) {
      console.error('🔒 Authentication callback error:', error);

      // Determine error type and redirect appropriately
      const errorParam = this.isSecurityError(error) ? 'security_error' : 'server_error';
      res.redirect(`${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=${errorParam}`);
    }
  }

  private isSecurityError(error: any): boolean {
    // Check if error is security-related
    const securityKeywords = ['security', 'validation', 'pkce', 'nonce', 'state', 'csrf'];
    const errorMessage = error?.message?.toLowerCase() || '';
    return securityKeywords.some(keyword => errorMessage.includes(keyword));
  }

  getStrategy(): AuthStrategy {
    return this.strategy;
  }
}
