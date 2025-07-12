import { Router } from 'express';
import { UserController } from '../controllers/UserController';
import { requireAuthenticatedActiveUser, requireAdmin, requireModerator } from '../middleware/auth';

const router: Router = Router();
const userController = new UserController();

// All user routes require authentication and active account
router.use(requireAuthenticatedActiveUser);

// User profile routes (accessible to all authenticated users)
router.get('/profile', userController.getProfile);
router.put('/profile', userController.updateUser); // Users can update their own profile

// Admin and moderator routes
router.get('/', requireModerator, userController.getUsers);
router.get('/:id', requireModerator, userController.getUserById);

// Admin only routes
router.get('/stats', requireAdmin, userController.getUserStats);
router.post('/', requireAdmin, userController.createUser);
router.put('/:id', requireAdmin, userController.updateUser);
router.delete('/:id', requireAdmin, userController.deleteUser);

export default router;
