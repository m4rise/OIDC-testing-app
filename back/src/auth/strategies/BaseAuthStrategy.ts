import { Request, Response } from 'express';
import { AuthService } from '../../services/AuthService';

export interface AuthStrategy {
  initiateLogin(req: Request, res: Response, next: Function): Promise<void> | void;
  handleCallback(req: Request, res: Response, next: Function): Promise<void>;
}

export abstract class BaseAuthStrategy implements AuthStrategy {
  protected authService: AuthService;

  constructor() {
    this.authService = new AuthService();
  }

  abstract initiateLogin(req: Request, res: Response, next: Function): Promise<void> | void;
  abstract handleCallback(req: Request, res: Response, next: Function): Promise<void>;
}
