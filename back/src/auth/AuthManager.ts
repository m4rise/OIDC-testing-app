import { Request, Response } from 'express';
import { AuthStrategy } from './strategies/BaseAuthStrategy';
import { OpenIDConnectStrategy } from './strategies/OpenIDConnectStrategy';

export class AuthManager {
  private strategy: AuthStrategy;

  constructor() {
    this.strategy = this.createStrategy();
  }

  private createStrategy(): AuthStrategy {
    // Always use OpenIDConnectStrategy - it handles both mock and real OIDC based on environment
    console.log('🔐 Using OpenID Connect Strategy');
    return new OpenIDConnectStrategy();
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
      const failureUrl = process.env.LOGIN_FAILURE_REDIRECT_URL ||
        `${process.env.FRONTEND_URL || 'https://front.localhost'}/login?error=auth_error`;
      res.redirect(failureUrl);
    }
  }
}
