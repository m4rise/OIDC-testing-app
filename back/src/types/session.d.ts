import 'express-session';

declare module 'express-session' {
  interface SessionData {
    returnTo?: string;
  }
}

declare global {
  namespace Express {
    interface Request {
      session: import('express-session').Session & Partial<import('express-session').SessionData> & {
        returnTo?: string;
      };
    }
  }
}
