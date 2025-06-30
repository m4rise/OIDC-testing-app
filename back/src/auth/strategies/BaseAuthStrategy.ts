import { Request, Response } from 'express';
import { AuthService } from '../../services/AuthService';

export interface AuthParams {
  codeVerifier?: string;
  codeChallenge?: string;
  nonce?: string;
  state?: string;
  acrValues?: string;
}

export interface AuthStrategy {
  initiateLogin(req: Request, res: Response, next: Function): Promise<void> | void;
  handleCallback(req: Request, res: Response, next: Function): Promise<void>;
  generateAuthParams(): AuthParams;
  validateCallback(req: Request): Promise<boolean>;
}

export abstract class BaseAuthStrategy implements AuthStrategy {
  protected authService: AuthService;

  constructor() {
    this.authService = new AuthService();
  }

  protected storeInSession(req: Request, params: AuthParams): void {
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) {
        (req.session as any)[key] = value;
      }
    });
  }

  protected getFromSession(req: Request, key: string): any {
    return (req.session as any)?.[key];
  }

  protected clearSessionParams(req: Request, params: string[]): void {
    params.forEach(param => {
      delete (req.session as any)?.[param];
    });
  }

  // User management methods
  protected async findOrCreateUser(profile: any): Promise<any> {
    return this.authService.findOrCreateUserFromOIDC(profile);
  }

  protected async updateLastLogin(userId: string): Promise<void> {
    return this.authService.updateLastLogin(userId);
  }

  abstract initiateLogin(req: Request, res: Response, next: Function): Promise<void> | void;
  abstract handleCallback(req: Request, res: Response, next: Function): Promise<void>;
  abstract generateAuthParams(): AuthParams;
  abstract validateCallback(req: Request): Promise<boolean>;
}
