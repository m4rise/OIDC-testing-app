import express, { Router } from 'express';
import { MockOidcController } from '../controllers/MockOidcController';

const router: Router = express.Router();
const mockOidcController = new MockOidcController();

// OIDC Discovery endpoint
router.get('/.well-known/openid_configuration', mockOidcController.discovery);

// JWKS endpoint for JWT verification
router.get('/.well-known/jwks.json', mockOidcController.jwks);

// Authorization endpoint (GET for login form, POST for authentication)
router.get('/auth', mockOidcController.authorize);
router.post('/auth', express.urlencoded({ extended: true }), mockOidcController.handleAuth);

// Token endpoint (supports authorization_code and refresh_token grants)
router.post('/token', express.json(), mockOidcController.token);

// UserInfo endpoint
router.get('/userinfo', mockOidcController.userinfo);

// Token introspection endpoint (RFC 7662)
router.post('/introspect', express.json(), mockOidcController.introspect);

export default router;
