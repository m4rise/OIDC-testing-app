/**
 * Centralized Environment Configuration
 *
 * This module provides a single source of truth for all environment variables
 * and their default values throughout the application.
 */

import dotenv from 'dotenv';

// Load environment variables first
dotenv.config();

export interface AppConfig {
  // Application
  nodeEnv: string;
  port: number;
  isDevelopment: boolean;
  isProduction: boolean;

  // URLs
  backendUrl: string;
  frontendUrl: string;
  internalBackendUrl: string;
  internalFrontendUrl: string;

  // Database
  database: {
    host: string;
    port: number;
    username: string;
    password: string;
    database: string;
  };

  // Session
  session: {
    secret: string;
    rollingMinutes: number;
    maxAgeMinutes: number;
    cookieName?: string;
    cookieDomain?: string;
  };

  // OIDC
  oidc: {
    clientId: string;
    clientSecret: string;
    issuer?: string;
    callbackUrl: string;
    acrValues?: string;
  };

  // Development Authentication Bypass
  dev: {
    bypassAuth: boolean;
    user: {
      id: string;
      email: string;
      name: string;
    };
    jwt: {
      expiryMinutes: number;
    };
    includeEnhancedCallbackParams: boolean;
  };

  // Frontend Redirects
  redirects: {
    loginSuccessPath: string;
    loginFailurePath: string;
  };
}

function getConfig(): AppConfig {
  const nodeEnv = process.env.NODE_ENV || 'development';
  const isDevelopment = nodeEnv === 'development';
  const isProduction = nodeEnv === 'production';

  return {
    // Application
    nodeEnv,
    port: parseInt(process.env.PORT || '5000'),
    isDevelopment,
    isProduction,

    // URLs
    backendUrl: process.env.BACKEND_URL || 'https://node.localhost',
    frontendUrl: process.env.FRONTEND_URL || 'https://front.localhost',
    internalBackendUrl: process.env.INTERNAL_BACKEND_URL || 'http://localhost:5000',
    internalFrontendUrl: process.env.INTERNAL_FRONTEND_URL || 'http://localhost:4200',

    // Database
    database: {
      host: process.env.PG_HOST || 'postgres',
      port: parseInt(process.env.PG_PORT || '5432'),
      username: process.env.POSTGRES_USER || 'postgres',
      password: process.env.POSTGRES_PASSWORD || 'password',
      database: process.env.POSTGRES_DB || 'boilerplate',
    },

    // Session
    session: {
      secret: process.env.SESSION_SECRET || 'your-secret-key',
      rollingMinutes: parseInt(process.env.SESSION_ROLLING_MINUTES || '10'),
      maxAgeMinutes: parseInt(process.env.SESSION_MAXAGE_MINUTES || '60'),
      cookieName: process.env.SESSION_COOKIE_NAME,
      cookieDomain: process.env.COOKIE_DOMAIN,
    },

    // OIDC
    oidc: {
      clientId: process.env.OIDC_CLIENT_ID || 'mock-client',
      clientSecret: process.env.OIDC_CLIENT_SECRET || 'mock-secret',
      issuer: process.env.OIDC_ISSUER,
      callbackUrl: process.env.OIDC_CALLBACK_URL || `${process.env.BACKEND_URL || 'https://node.localhost'}/api/auth/callback`,
      acrValues: process.env.OIDC_ACR_VALUES,
    },

    // Development Authentication Bypass
    dev: {
      bypassAuth: process.env.DEV_BYPASS_AUTH === 'true',
      user: {
        id: process.env.DEV_USER_ID || 'dev-user-123',
        email: process.env.DEV_USER_EMAIL || 'dev.user@example.com',
        name: process.env.DEV_USER_NAME || 'Dev User',
      },
      jwt: {
        expiryMinutes: parseInt(process.env.DEV_JWT_EXPIRY_MINUTES || '60'),
      },
      includeEnhancedCallbackParams: process.env.DEV_INCLUDE_ENHANCED_CALLBACK_PARAMS === 'true',
    },

    // Frontend Redirects
    redirects: {
      loginSuccessPath: process.env.LOGIN_SUCCESS_REDIRECT_PATH || '/',
      loginFailurePath: process.env.LOGIN_FAILURE_REDIRECT_PATH || '/login?error=auth_failed',
    },
  };
}

// Export singleton instance
export const config = getConfig();

// Export individual sections for convenience
export const { database, session, oidc, dev, redirects } = config;
