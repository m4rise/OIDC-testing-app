import { Router } from 'express';
import { AuthController } from '../controllers/AuthController';

const router: Router = Router();
const authController = new AuthController();

// Authentication routes
router.get('/login', authController.login);
router.get('/callback', authController.callback);
router.post('/callback', authController.callback); // Support both GET and POST for OIDC callback
router.post('/logout', authController.logout);
router.get('/logout', authController.logout); // Support GET for easier testing
router.get('/session', authController.getSession);
router.get('/check', authController.checkAuth);
router.get('/token-status', authController.getTokenStatus);
router.get('/token-info', authController.getTokenStatusPublic); // Public version with helpful messages
router.get('/session-debug', authController.getSessionDebug); // Debug session contents
router.post('/refresh-token', authController.refreshToken);

export default router;
