import { Request, Response, NextFunction } from 'express';

/**
 * Token information stored in session
 */
export interface TokenInfo {
  accessToken?: string;
  idToken?: string;
  refreshToken?: string;
  expiresAt?: number;
  tokenExpiry?: number; // ID token expiration (Unix timestamp in ms)
  refreshExpiry?: number; // Refresh token expiration (Unix timestamp in ms)
  lastRefresh?: number; // Last token refresh timestamp
}

/**
 * Enhanced session security middleware with OIDC token validation
 * Adds checks for session integrity, security, and token expiration
 */
export const sessionSecurity = async (req: Request, res: Response, next: NextFunction) => {
  try {
    // Check for session fixation attempts
    if (req.session && req.sessionID) {
      const sessionAge = Date.now() - (req.session as any).createdAt || 0;
      const maxSessionAge = 24 * 60 * 60 * 1000; // 24 hours

      // Regenerate session ID periodically for security
      if (sessionAge > maxSessionAge && req.isAuthenticated()) {
        console.log('🔄 Regenerating session ID for security');
        req.session.regenerate((err) => {
          if (err) {
            console.error('Session regeneration failed:', err);
          }
          next();
        });
        return;
      }

      // Enhanced: Check OIDC token expiration for authenticated users
      if (req.isAuthenticated() && (req.session as any).tokenInfo) {
        const tokenInfo: TokenInfo = (req.session as any).tokenInfo;
        const now = Date.now();

        // Check if ID token has expired
        if (tokenInfo.tokenExpiry && now > tokenInfo.tokenExpiry) {
          console.log('🔒 ID token expired, checking refresh token availability');

          // Try to refresh token if refresh token exists and isn't expired
          if (tokenInfo.refreshToken && tokenInfo.refreshExpiry && now < tokenInfo.refreshExpiry) {
            try {
              const refreshed = await refreshTokens(req, tokenInfo);
              if (refreshed) {
                console.log('✅ Token refreshed successfully');
                // Update session expiration based on new token
                updateSessionExpiration(req, (req.session as any).tokenInfo);
                return next();
              }
            } catch (error) {
              console.error('🔒 Token refresh failed:', error);
            }
          }

          // Force re-authentication if refresh failed or unavailable
          console.log('🔒 Forcing re-authentication due to expired token');
          req.logout((err) => {
            if (err) console.error('Logout error:', err);

            // Clear token info from session
            delete (req.session as any).tokenInfo;

            // Determine redirect URL based on request type
            if (req.xhr || req.headers.accept?.includes('application/json')) {
              // API request - return 401
              res.status(401).json({
                error: 'token_expired',
                message: 'Authentication token has expired. Please log in again.',
                requiresReauth: true
              });
            } else {
              // Browser request - redirect to login
              const returnTo = encodeURIComponent(req.originalUrl);
              res.redirect(`/api/auth/login?reason=token_expired&returnTo=${returnTo}`);
            }
          });
          return;
        }

        // Update session expiration to respect token lifetime
        updateSessionExpiration(req, tokenInfo);
      }
    }

    next();
  } catch (error) {
    console.error('Session security middleware error:', error);
    next(error);
  }
};

/**
 * Refresh OIDC tokens using refresh token
 */
async function refreshTokens(req: Request, tokenInfo: TokenInfo): Promise<boolean> {
  const useMockOIDC = process.env.NODE_ENV === 'development' && process.env.USE_MOCK_OIDC === 'true';

  if (useMockOIDC) {
    return await refreshMockTokens(req, tokenInfo);
  } else {
    return await refreshRealTokens(req, tokenInfo);
  }
}

/**
 * Refresh tokens with real OIDC provider
 */
async function refreshRealTokens(req: Request, tokenInfo: TokenInfo): Promise<boolean> {
  try {
    const tokenEndpoint = `${process.env.OIDC_ISSUER}/token`;

    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': `Basic ${Buffer.from(`${process.env.OIDC_CLIENT_ID}:${process.env.OIDC_CLIENT_SECRET}`).toString('base64')}`
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tokenInfo.refreshToken!,
        scope: 'openid profile email'
      })
    });

    if (!response.ok) {
      console.error('Token refresh failed:', response.status, response.statusText);
      return false;
    }

    const tokens = await response.json();

    // Update token info in session
    const updatedTokenInfo: TokenInfo = {
      ...tokenInfo,
      accessToken: tokens.access_token,
      idToken: tokens.id_token,
      refreshToken: tokens.refresh_token || tokenInfo.refreshToken, // Keep old refresh token if new one not provided
      expiresAt: Date.now() + (tokens.expires_in * 1000),
      lastRefresh: Date.now()
    };

    // Decode ID token to get expiration
    if (tokens.id_token) {
      const idTokenPayload = JSON.parse(Buffer.from(tokens.id_token.split('.')[1], 'base64').toString());
      updatedTokenInfo.tokenExpiry = idTokenPayload.exp * 1000;
    }

    (req.session as any).tokenInfo = updatedTokenInfo;

    return true;
  } catch (error) {
    console.error('Real token refresh error:', error);
    return false;
  }
}

/**
 * Refresh tokens with mock OIDC provider
 */
async function refreshMockTokens(req: Request, tokenInfo: TokenInfo): Promise<boolean> {
  try {
    const tokenEndpoint = `https://node.localhost/mock-oidc/token`;

    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: tokenInfo.refreshToken!,
        client_id: process.env.OIDC_CLIENT_ID || 'mock-client-id',
        client_secret: process.env.OIDC_CLIENT_SECRET || 'mock-client-secret'
      })
    });

    if (!response.ok) {
      console.error('Mock token refresh failed:', response.status, response.statusText);
      return false;
    }

    const tokens = await response.json();

    // Update token info in session
    const updatedTokenInfo: TokenInfo = {
      ...tokenInfo,
      accessToken: tokens.access_token,
      idToken: tokens.id_token,
      refreshToken: tokens.refresh_token || tokenInfo.refreshToken,
      expiresAt: Date.now() + (tokens.expires_in * 1000),
      lastRefresh: Date.now()
    };

    // Decode ID token to get expiration
    if (tokens.id_token) {
      const idTokenPayload = JSON.parse(Buffer.from(tokens.id_token.split('.')[1], 'base64').toString());
      updatedTokenInfo.tokenExpiry = idTokenPayload.exp * 1000;
    }

    (req.session as any).tokenInfo = updatedTokenInfo;

    return true;
  } catch (error) {
    console.error('Mock token refresh error:', error);
    return false;
  }
}

/**
 * Update session expiration to respect token lifetime
 */
function updateSessionExpiration(req: Request, tokenInfo: TokenInfo): void {
  if (!tokenInfo.tokenExpiry || !req.session.cookie) return;

  const now = Date.now();
  const tokenTimeLeft = tokenInfo.tokenExpiry - now;
  const sessionMaxAge = req.session.cookie.maxAge || (8 * 60 * 60 * 1000); // Default 8 hours

  // Use the shorter of session maxAge or token time left
  const actualMaxAge = Math.min(sessionMaxAge, tokenTimeLeft);

  if (actualMaxAge > 0) {
    req.session.cookie.maxAge = actualMaxAge;
    console.log(`🔄 Session expiration updated: ${Math.round(actualMaxAge / 1000 / 60)} minutes remaining`);
  }
}
