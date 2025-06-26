export interface OIDCConfig {
  clientId: string;
  clientSecret: string;
  issuer: string;
  callbackURL: string;
  acrValues?: string;
  useMockOIDC: boolean;
}

export class AuthConfigValidator {
  static validateEnvironment(): OIDCConfig {
    const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

    const config: OIDCConfig = {
      clientId: process.env.OIDC_CLIENT_ID || '',
      clientSecret: process.env.OIDC_CLIENT_SECRET || '',
      issuer: process.env.OIDC_ISSUER || '',
      callbackURL: process.env.OIDC_CALLBACK_URL || 'https://node.localhost/api/auth/callback',
      acrValues: process.env.OIDC_ACR_VALUES,
      useMockOIDC
    };

    if (!useMockOIDC) {
      const missingVars = this.getMissingVariables(config);
      if (missingVars.length > 0) {
        console.warn('🔒 OIDC configuration incomplete. Missing variables:', missingVars);
        console.warn('To enable OIDC authentication, set the following environment variables:');
        missingVars.forEach(variable => console.warn(`  - ${variable}`));
        console.warn('To use Mock OIDC for development, set USE_MOCK_OIDC=true');
        throw new Error(`Missing OIDC configuration: ${missingVars.join(', ')}`);
      }
    }

    return config;
  }

  private static getMissingVariables(config: OIDCConfig): string[] {
    const required = ['clientId', 'clientSecret', 'issuer'];
    return required.filter(key => !config[key as keyof OIDCConfig]);
  }

  static isConfigured(): boolean {
    try {
      this.validateEnvironment();
      return true;
    } catch {
      return false;
    }
  }

  static getStrategy(): 'mock' | 'real' | null {
    try {
      const config = this.validateEnvironment();
      return config.useMockOIDC ? 'mock' : 'real';
    } catch {
      return null;
    }
  }
}
