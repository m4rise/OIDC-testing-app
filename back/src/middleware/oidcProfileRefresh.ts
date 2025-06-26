import { Request, Response, NextFunction } from 'express';
import { User } from '../entities/User';
import { AuthService } from '../services/AuthService';

/**
 * Middleware to check and refresh stale OIDC profiles
 * Use this on sensitive endpoints that require up-to-date permissions
 */
export const refreshStaleOIDCProfile = (maxAgeHours: number = 24) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      if (!req.isAuthenticated() || !req.user) {
        return next();
      }

      const user = req.user as User;

      // Check if profile is stale
      if (user.oidcSubject && user.oidcIssuer) {
        const authService = new AuthService();

        if (authService.shouldRefreshProfile(user, maxAgeHours)) {
          console.log(`⚠️  OIDC profile is stale for user ${user.email}, consider refreshing`);

          // Option 1: Log warning and continue
          // (Actual refresh requires OAuth2 setup with refresh tokens)

          // Option 2: Force re-authentication for critical operations
          // if (req.path.includes('/admin/')) {
          //   return res.status(401).json({
          //     error: 'Profile outdated, please re-authenticate',
          //     requiresReauth: true
          //   });
          // }
        }
      }

      next();
    } catch (error) {
      console.error('OIDC profile refresh middleware error:', error);
      next(); // Continue despite error
    }
  };
};

/**
 * Middleware to enforce fresh profiles for admin operations
 */
export const requireFreshProfile = (maxAgeHours: number = 1) => {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      if (!req.isAuthenticated() || !req.user) {
        res.status(401).json({ error: 'Authentication required' });
        return;
      }

      const user = req.user as User;

      if (user.oidcSubject && user.isProfileStale) {
        res.status(401).json({
          error: 'Profile outdated, please re-authenticate',
          requiresReauth: true,
          profileAge: user.profileAge,
          maxAge: maxAgeHours * 60 * 60 * 1000
        });
        return;
      }

      next();
    } catch (error) {
      console.error('Fresh profile middleware error:', error);
      res.status(500).json({ error: 'Profile validation failed' });
    }
  };
};
