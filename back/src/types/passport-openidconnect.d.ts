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
    // Security and OIDC extension options
    nonce?: boolean | string;
    acrValues?: string;
    passReqToCallback?: boolean;
    prompt?: string;
    display?: string;
    maxAge?: number;
    loginHint?: string;
    idTokenHint?: string;
    claims?: any;
    responseMode?: string;
    customHeaders?: any;
    agent?: any;
    proxy?: boolean;
  }

  type VerifyCallback = (
    issuer: string,
    sub: string,
    profile: any,
    accessToken: string,
    refreshToken: string,
    done: (error: any, user?: any) => void
  ) => void;

  type VerifyCallbackWithRequest = (
    req: any,
    issuer: string,
    sub: string,
    profile: any,
    accessToken: string,
    refreshToken: string,
    done: (error: any, user?: any) => void
  ) => void;

  export class Strategy extends Strategy {
    constructor(options: OpenIDConnectStrategyOptions, verify: VerifyCallback | VerifyCallbackWithRequest);
  }
}
