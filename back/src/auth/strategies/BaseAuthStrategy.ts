import { Request, Response } from 'express';
import { AuthService } from '../../services/AuthService';
import {
  validateState,
  validatePKCE,
  validateRedirectUri,
  validateAuthorizationCode,
  validateNonce,
  validateIssuer,
  decodeJWTPayload
} from '../../utils/security-validator';

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

  // Security validation methods
  protected validateAuthorizationCode(code: string): void {
    return validateAuthorizationCode(code);
  }

  protected validateState(receivedState: string, sessionState: string): void {
    return validateState(receivedState, sessionState);
  }

  protected validateRedirectUri(currentUri: string, expectedUri: string): void {
    return validateRedirectUri(currentUri, expectedUri);
  }

  protected validatePKCE(codeVerifier: string, codeChallenge: string): void {
    return validatePKCE(codeVerifier, codeChallenge);
  }

  protected validateNonce(receivedNonce: string, sessionNonce: string): void {
    return validateNonce(receivedNonce, sessionNonce);
  }

  protected validateIssuer(receivedIssuer: string, expectedIssuer: string): void {
    return validateIssuer(receivedIssuer, expectedIssuer);
  }

  protected decodeJWTPayload(token: string): any {
    return decodeJWTPayload(token);
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
