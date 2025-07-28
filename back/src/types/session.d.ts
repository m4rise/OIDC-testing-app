import 'express-session';

declare global {
  namespace Express {
    namespace session {
      interface SessionData {
        returnTo?: string;
        jwtExpiry?: number;
        passport?: {
          user?: any;
        };
      }
    }
  }
}
