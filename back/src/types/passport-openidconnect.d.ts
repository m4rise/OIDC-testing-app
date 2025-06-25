declare module 'passport-openidconnect' {
  import { Strategy } from 'passport-strategy';

  interface OpenIDConnectStrategyOptions {
    issuer: string;
    authorizationURL: string;
    tokenURL: string;
    userInfoURL: string;
    clientID: string;
    clientSecret: string;
    callbackURL: string;
    scope: string;
  }

  type VerifyCallback = (
    issuer: string,
    sub: string,
    profile: any,
    accessToken: string,
    refreshToken: string,
    done: (error: any, user?: any) => void
  ) => void;

  export class Strategy extends Strategy {
    constructor(options: OpenIDConnectStrategyOptions, verify: VerifyCallback);
  }
}
