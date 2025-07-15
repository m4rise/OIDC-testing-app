import { Router } from 'express';
import { AuthController } from '../controllers/AuthController';
import { requireAuth } from '../middleware/auth';

const router: Router = Router();
const authController = new AuthController();

// Public authentication routes (no middleware needed)
router.get('/login', authController.login);
router.get('/callback', authController.callback);
router.post('/callback', authController.callback); // Support both GET and POST for OIDC callback
router.post('/logout', authController.logout);
router.get('/logout', authController.logout); // Support GET for easier testing
router.get('/session', authController.getSession);
router.get('/check', authController.checkAuth);
router.get('/session-debug', authController.getSessionDebug); // Debug session contents

export default router;
