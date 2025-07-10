import express, { Router } from 'express';
import { MockOidcController } from '../controllers/MockOidcController';

const router: Router = express.Router();
const mockOidcController = new MockOidcController();

// Add debugging middleware to see what routes are being hit
router.use((req, res, next) => {
  console.log(`🛤️  Mock OIDC Route: ${req.method} ${req.path} (Original URL: ${req.originalUrl})`);
  next();
});

// Simple test route
router.get('/simple-test', function(req, res) {
  console.log('🟢 Simple test route called');
  res.json({ status: 'simple test works' });
});

// OIDC Discovery endpoint with properly escaped dots
router.get('/\\.well-known/openid-configuration', mockOidcController.discovery);

// Alternative discovery endpoint for testing
router.get('/discovery', mockOidcController.discovery);

// JWKS endpoint for JWT verification with escaped dots
router.get('/\\.well-known/jwks\\.json', mockOidcController.jwks);

// Test dashboard for comprehensive validation testing
router.get('/test-dashboard', mockOidcController.testDashboard);

// Authorization endpoint (GET for login form, POST for authentication)
router.get('/auth', mockOidcController.authorize);
router.post('/auth', mockOidcController.handleAuth);

// Token endpoint (supports authorization_code and refresh_token grants)
router.post('/token', mockOidcController.token);

// UserInfo endpoint
router.get('/userinfo', mockOidcController.userinfo);

// Token introspection endpoint (RFC 7662)
router.post('/introspect', mockOidcController.introspect);

export default router;
