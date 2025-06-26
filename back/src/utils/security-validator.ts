import crypto from 'crypto';

/**
 * Security validation utilities for OIDC flow
 * Note: JWT validation is handled by Passport.js OpenIDConnect strategy
 */

export interface SecurityValidationError extends Error {
  code: string;
  details?: any;
}

/**
 * Validate state parameter to prevent CSRF attacks
 */
export function validateState(receivedState: string | undefined, sessionState: string | undefined): void {
  if (!receivedState || !sessionState || receivedState !== sessionState) {
    const error = new Error('State parameter validation failed - potential CSRF attack') as SecurityValidationError;
    error.code = 'STATE_MISMATCH';
    error.details = {
      received: receivedState?.substring(0, 10) + '...',
      expected: sessionState?.substring(0, 10) + '...'
    };
    throw error;
  }
}

/**
 * Validate PKCE code verifier against code challenge
 */
export function validatePKCE(codeVerifier: string, codeChallenge: string): void {
  const computedChallenge = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64url');

  if (computedChallenge !== codeChallenge) {
    const error = new Error('PKCE validation failed - code verifier does not match challenge') as SecurityValidationError;
    error.code = 'PKCE_MISMATCH';
    error.details = {
      computed: computedChallenge.substring(0, 10) + '...',
      expected: codeChallenge.substring(0, 10) + '...'
    };
    throw error;
  }
}

/**
 * Validate redirect URI matches expected callback URL
 */
export function validateRedirectUri(receivedUri: string, expectedUri: string): void {
  if (receivedUri !== expectedUri) {
    const error = new Error('Redirect URI validation failed') as SecurityValidationError;
    error.code = 'REDIRECT_URI_MISMATCH';
    error.details = {
      received: receivedUri,
      expected: expectedUri
    };
    throw error;
  }
}

/**
 * Validate authorization code format
 */
export function validateAuthorizationCode(code: string | undefined): void {
  if (!code || typeof code !== 'string' || code.length < 10) {
    const error = new Error('Invalid authorization code') as SecurityValidationError;
    error.code = 'INVALID_AUTH_CODE';
    throw error;
  }
}

/**
 * Validate nonce in ID token payload
 */
export function validateNonce(tokenNonce: string | undefined, sessionNonce: string | undefined): void {
  if (sessionNonce && tokenNonce !== sessionNonce) {
    const error = new Error('Nonce validation failed - potential replay attack') as SecurityValidationError;
    error.code = 'NONCE_MISMATCH';
    error.details = {
      token: tokenNonce?.substring(0, 10) + '...',
      session: sessionNonce?.substring(0, 10) + '...'
    };
    throw error;
  }
}

/**
 * Validate issuer matches expected value
 */
export function validateIssuer(tokenIssuer: string | undefined, expectedIssuer: string): void {
  if (!tokenIssuer || tokenIssuer !== expectedIssuer) {
    const error = new Error('Issuer validation failed') as SecurityValidationError;
    error.code = 'ISSUER_MISMATCH';
    error.details = {
      token: tokenIssuer,
      expected: expectedIssuer
    };
    throw error;
  }
}

/**
 * Check if error is a security validation error
 */
export function isSecurityError(error: any): error is SecurityValidationError {
  return error && typeof error.code === 'string' && error.code.includes('_');
}

/**
 * Simple JWT payload decoder (without verification - use only for non-security checks)
 * For security-critical validation, rely on Passport.js
 */
export function decodeJWTPayload(token: string): any {
  try {
    const parts = token.split('.');
    if (parts.length !== 3 || !parts[1]) {
      throw new Error('Invalid JWT format');
    }

    // Fix for base64url decoding
    const base64Payload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const payload = Buffer.from(base64Payload, 'base64').toString('utf-8');
    return JSON.parse(payload);
  } catch (error) {
    throw new Error('Failed to decode JWT payload');
  }
}
