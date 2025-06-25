import { Router } from 'express';
import { UserController } from '../controllers/UserController';
import { requireAuth, requireRole, requirePermission, requireActiveAccount } from '../middleware/auth';
import { UserRole } from '../entities/User';

const router: Router = Router();
const userController = new UserController();

// All user routes require authentication and active account
router.use(requireAuth);
router.use(requireActiveAccount);

// User profile routes (accessible to all authenticated users)
router.get('/profile', userController.getProfile);
router.put('/profile', userController.updateUser); // Users can update their own profile

// Admin and moderator routes
router.get('/', requireRole([UserRole.ADMIN, UserRole.MODERATOR]), userController.getUsers);
router.get('/stats', requireRole(UserRole.ADMIN), userController.getUserStats);
router.get('/:id', requireRole([UserRole.ADMIN, UserRole.MODERATOR]), userController.getUserById);

// Admin only routes
router.post('/', requireRole(UserRole.ADMIN), userController.createUser);
router.put('/:id', requireRole(UserRole.ADMIN), userController.updateUser);
router.delete('/:id', requireRole(UserRole.ADMIN), userController.deleteUser);

export default router;
