import { Router } from 'express';
import { AuthController } from '../controllers/AuthController';

const router: Router = Router();
const authController = new AuthController();

// Authentication routes
router.get('/login', authController.login);
router.get('/callback', authController.callback);
router.post('/callback', authController.callback); // Support both GET and POST for OIDC callback
router.post('/logout', authController.logout);
router.get('/session', authController.getSession);
router.get('/check', authController.checkAuth);

export default router;
