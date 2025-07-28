import { Router } from 'express';
import { UserController } from '../controllers/UserController';
import {
  requireActiveUserWithPermission,
  requireActiveUserWithRole
} from '../middleware/auth';

const router: Router = Router();
const userController = new UserController();

// User profile routes (accessible to all authenticated active users)
router.get('/profile', requireActiveUserWithPermission('api:user:read:self'), userController.getProfile);
router.put('/profile', requireActiveUserWithPermission('api:user:write:self'), userController.updateUser);

// Admin only routes
router.get('/stats', requireActiveUserWithRole('admin'), userController.getUserStats);

// Moderator and admin routes
router.get('/', requireActiveUserWithPermission('api:user:read:*'), userController.getUsers);
router.get('/:id', requireActiveUserWithPermission('api:user:read:*'), userController.getUserById);
router.post('/', requireActiveUserWithPermission('api:user:write:*'), userController.createUser);
router.put('/:id', requireActiveUserWithPermission('api:user:write:*'), userController.updateUser);
router.delete('/:id', requireActiveUserWithPermission('api:user:delete:*'), userController.deleteUser);

export default router;
