/**
 * OIDC Test Scenarios for Comprehensive Validation Testing
 *
 * This module provides various test scenarios to validate the OIDC implementation
 * against edge cases, security vulnerabilities, and specification compliance.
 */

export interface TestScenario {
  name: string;
  description: string;
  params: Record<string, string>;
  expectedResult: 'success' | 'error' | 'redirect_error';
  expectedError?: string;
  category: 'basic' | 'security' | 'pkce' | 'edge_case' | 'malicious';
}

export const OIDC_TEST_SCENARIOS: TestScenario[] = [
  // Basic Valid Scenarios
  {
    name: 'valid_basic_flow',
    description: 'Standard OIDC authorization code flow with minimal parameters',
    params: {
      client_id: 'mock-client',
      redirect_uri: 'https://node.localhost/api/auth/callback',
      response_type: 'code',
      scope: 'openid profile email',
      state: 'random-state-123',
      nonce: 'random-nonce-456'
    },
    expectedResult: 'success',
    category: 'basic'
  },
  {
    name: 'valid_with_pkce',
    description: 'OIDC flow with PKCE code challenge',
    params: {
      client_id: 'mock-client',
      redirect_uri: 'https://node.localhost/api/auth/callback',
      response_type: 'code',
      scope: 'openid profile',
      state: 'state-with-pkce',
      nonce: 'nonce-with-pkce',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'S256'
    },
    expectedResult: 'success',
    category: 'pkce'
  },

  // Security Test Scenarios
  {
    name: 'invalid_client_id',
    description: 'Test with wrong client_id',
    params: {
      client_id: 'malicious-client',
      redirect_uri: 'https://node.localhost/api/auth/callback',
      response_type: 'code',
      scope: 'openid',
      state: 'state-123'
    },
    expectedResult: 'error',
    expectedError: 'Invalid client_id',
    category: 'security'
  },
  {
    name: 'invalid_redirect_uri',
    description: 'Test with unauthorized redirect URI',
    params: {
      client_id: 'mock-client',
      redirect_uri: 'https://malicious.site/callback',
      response_type: 'code',
      scope: 'openid',
      state: 'state-123'
    },
    expectedResult: 'error',
    expectedError: 'Invalid redirect_uri',
    category: 'security'
  },
  {
    name: 'missing_openid_scope',
    description: 'Test without required openid scope',
    params: {
      client_id: 'mock-client',
      redirect_uri: 'https://node.localhost/api/auth/callback',
      response_type: 'code',
      scope: 'profile email',
      state: 'state-123'
    },
    expectedResult: 'redirect_error',
    expectedError: 'invalid_scope',
    category: 'security'
  },

  // PKCE Test Scenarios
  {
    name: 'pkce_invalid_method',
    description: 'Test PKCE with unsupported method',
    params: {
      client_id: 'mock-client',
      redirect_uri: 'https://node.localhost/api/auth/callback',
      response_type: 'code',
      scope: 'openid',
      state: 'state-123',
      code_challenge: 'plaintext-challenge',
      code_challenge_method: 'plain'
    },
    expectedResult: 'redirect_error',
    expectedError: 'invalid_request',
    category: 'pkce'
  },
  {
    name: 'pkce_short_challenge',
    description: 'Test PKCE with too short code challenge',
    params: {
      client_id: 'mock-client',
      redirect_uri: 'https://node.localhost/api/auth/callback',
      response_type: 'code',
      scope: 'openid',
      state: 'state-123',
      code_challenge: 'short',
      code_challenge_method: 'S256'
    },
    expectedResult: 'redirect_error',
    expectedError: 'invalid_request',
    category: 'pkce'
  },

  // Edge Cases and Malicious Scenarios
  {
    name: 'unsupported_response_type',
    description: 'Test with implicit flow',
    params: {
      client_id: 'mock-client',
      redirect_uri: 'https://node.localhost/api/auth/callback',
      response_type: 'token',
      scope: 'openid',
      state: 'state-123'
    },
    expectedResult: 'redirect_error',
    expectedError: 'unsupported_response_type',
    category: 'edge_case'
  },
  {
    name: 'missing_state',
    description: 'Test without state parameter (CSRF vulnerability)',
    params: {
      client_id: 'mock-client',
      redirect_uri: 'https://node.localhost/api/auth/callback',
      response_type: 'code',
      scope: 'openid profile'
    },
    expectedResult: 'success', // Should succeed but log warning
    category: 'security'
  },
  {
    name: 'missing_nonce',
    description: 'Test without nonce parameter (replay attack vulnerability)',
    params: {
      client_id: 'mock-client',
      redirect_uri: 'https://node.localhost/api/auth/callback',
      response_type: 'code',
      scope: 'openid profile',
      state: 'state-123'
    },
    expectedResult: 'success', // Should succeed but log warning
    category: 'security'
  },
  {
    name: 'sql_injection_attempt',
    description: 'Test with malicious SQL injection in parameters',
    params: {
      client_id: 'mock-client',
      redirect_uri: 'https://node.localhost/api/auth/callback',
      response_type: 'code',
      scope: "openid'; DROP TABLE users; --",
      state: 'state-123'
    },
    expectedResult: 'redirect_error',
    expectedError: 'invalid_scope',
    category: 'malicious'
  },
  {
    name: 'xss_attempt',
    description: 'Test with XSS payload in state parameter',
    params: {
      client_id: 'mock-client',
      redirect_uri: 'https://node.localhost/api/auth/callback',
      response_type: 'code',
      scope: 'openid',
      state: '<script>alert("xss")</script>'
    },
    expectedResult: 'success', // Should be handled safely
    category: 'malicious'
  }
];

export class OidcTestRunner {
  private baseUrl: string;

  constructor(baseUrl: string = 'https://node.localhost/') {
    this.baseUrl = baseUrl;
  }

  /**
   * Generate test URL for a specific scenario
   */
  generateTestUrl(scenario: TestScenario): string {
    const url = new URL(`${this.baseUrl}/api/mock-oidc/auth`);
    Object.entries(scenario.params).forEach(([key, value]) => {
      url.searchParams.set(key, value);
    });
    return url.toString();
  }

  /**
   * Generate all test URLs grouped by category
   */
  generateAllTestUrls(): Record<string, { scenario: TestScenario; url: string }[]> {
    const grouped: Record<string, { scenario: TestScenario; url: string }[]> = {};

    OIDC_TEST_SCENARIOS.forEach(scenario => {
      if (!grouped[scenario.category]) {
        grouped[scenario.category] = [];
      }
      const categoryGroup = grouped[scenario.category];
      if (categoryGroup) {
        categoryGroup.push({
          scenario,
          url: this.generateTestUrl(scenario)
        });
      }
    });

    return grouped;
  }

  /**
   * Generate curl commands for testing token endpoint
   */
  generateTokenTestCommands(): string[] {
    const commands = [
      // Valid Basic Auth
      `curl -k -X POST https://node.localhost//api/mock-oidc/token \\
  -H "Authorization: Basic $(echo -n 'mock-client:mock-secret-123' | base64)" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=authorization_code&code=test-code&redirect_uri=https://node.localhost/api/auth/callback"`,

      // Invalid client credentials
      `curl -k -X POST https://node.localhost//api/mock-oidc/token \\
  -H "Authorization: Basic $(echo -n 'wrong:credentials' | base64)" \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=authorization_code&code=test-code&redirect_uri=https://node.localhost/api/auth/callback"`,

      // Missing Authorization header
      `curl -k -X POST https://node.localhost//api/mock-oidc/token \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=authorization_code&code=test-code&redirect_uri=https://node.localhost/api/auth/callback"`,

      // Client credentials in body (should work)
      `curl -k -X POST https://node.localhost//api/mock-oidc/token \\
  -H "Content-Type: application/x-www-form-urlencoded" \\
  -d "grant_type=authorization_code&code=test-code&redirect_uri=https://node.localhost/api/auth/callback&client_id=mock-client&client_secret=mock-secret-123"`
    ];

    return commands;
  }
}
