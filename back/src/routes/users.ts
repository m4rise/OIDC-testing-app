import { Router } from 'express';
import { UserController } from '../controllers/UserController';
import { requireAuthenticatedActiveUser } from '../middleware/auth';
import { requirePermission, requireRole } from '../middleware/rbac';

const router: Router = Router();
const userController = new UserController();

// All user routes require authentication and active account
router.use(requireAuthenticatedActiveUser);

// User profile routes (accessible to all authenticated users)
router.get('/profile', requirePermission('api:user:read:self'), userController.getProfile);
router.put('/profile', requirePermission('api:user:write:self'), userController.updateUser);

// Moderator and admin routes
router.get('/', requirePermission('api:user:read:*'), userController.getUsers);
router.get('/:id', requirePermission('api:user:read:*'), userController.getUserById);

// Admin only routes
router.get('/stats', requireRole('admin'), userController.getUserStats);
router.post('/', requirePermission('api:user:write:*'), userController.createUser);
router.put('/:id', requirePermission('api:user:write:*'), userController.updateUser);
router.delete('/:id', requirePermission('api:user:delete:*'), userController.deleteUser);

export default router;
