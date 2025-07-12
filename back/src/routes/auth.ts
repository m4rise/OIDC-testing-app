import { Router } from 'express';
import { AuthController } from '../controllers/AuthController';
import { requireAuth } from '../middleware/auth';

const router: Router = Router();
const authController = new AuthController();

// Public authentication routes (no middleware needed)
router.get('/login', authController.login);
router.get('/callback', authController.callback);
router.post('/callback', authController.callback); // Support both GET and POST for OIDC callback

// Protected routes (require authentication)
router.post('/logout', requireAuth, authController.logout);
router.get('/logout', requireAuth, authController.logout); // Support GET for easier testing
router.get('/session', requireAuth, authController.getSession);
router.get('/check', requireAuth, authController.checkAuth);
router.get('/session-debug', authController.getSessionDebug); // Debug session contents

export default router;
