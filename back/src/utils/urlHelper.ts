/**
 * URL Helper for managing internal vs external communication in containerized environments
 */

export type CommunicationContext = 'internal' | 'external';

export class UrlHelper {
  /**
   * Get the appropriate base URL for the given context
   * @param context - The communication context
   * @returns The base URL for the specified context
   */
  static getBaseUrl(context: CommunicationContext): string {
    if (context === 'internal') {
      // For internal communication (container talking to itself or other containers)
      return process.env.INTERNAL_BASE_URL || 'http://localhost:5000';
    } else {
      // For external communication (browser-facing URLs, redirects)
      return process.env.EXTERNAL_BASE_URL || 'https://node.localhost';
    }
  }

  /**
   * Get the appropriate OIDC issuer URL for the given context
   * @param context - The communication context
   * @returns The OIDC issuer URL for the specified context
   */
  static getOidcIssuerUrl(context: CommunicationContext): string {
    const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

    if (!useMockOIDC) {
      // For real OIDC, always use the configured issuer (external)
      return process.env.OIDC_ISSUER!;
    }

    if (context === 'internal') {
      // For internal discovery (container-to-self communication)
      return process.env.MOCK_OIDC_INTERNAL_ISSUER || 'http://localhost:5000/api/mock-oidc';
    } else {
      // For external URLs (redirects, frontend communication)
      return process.env.MOCK_OIDC_ISSUER || 'https://node.localhost/api/mock-oidc';
    }
  }

  /**
   * Get the appropriate frontend URL
   * @returns The frontend URL
   */
  static getFrontendUrl(): string {
    return process.env.FRONTEND_URL || 'https://front.localhost';
  }

  /**
   * Get the appropriate callback URL (always external as it's browser-facing)
   * @returns The OIDC callback URL
   */
  static getCallbackUrl(): string {
    return process.env.OIDC_CALLBACK_URL || `${this.getBaseUrl('external')}/api/auth/callback`;
  }

  /**
   * Get the appropriate URL for a specific API endpoint
   * @param endpoint - The API endpoint (e.g., 'token', 'auth', 'userinfo')
   * @param context - The communication context
   * @returns The complete endpoint URL
   */
  static getApiEndpointUrl(endpoint: string, context: CommunicationContext): string {
    const issuerUrl = this.getOidcIssuerUrl(context);
    return `${issuerUrl}/${endpoint}`;
  }
}
