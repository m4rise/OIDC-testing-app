import { Request, Response } from 'express';
import { UserService, CreateUserDto, UpdateUserDto } from '../services/UserService';
import { UserRole } from '../entities/User';

export class UserController {
  private userService: UserService;

  constructor() {
    this.userService = new UserService();
  }

  // Get current user profile
  getProfile = async (req: Request, res: Response): Promise<void> => {
    try {
      if (!req.user) {
        res.status(401).json({ error: 'Not authenticated' });
        return;
      }

      const user = await this.userService.getUserById((req.user as any).id);
      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      res.json({
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        fullName: user.fullName,
        role: user.role,
        isActive: user.isActive,
        createdAt: user.createdAt,
        lastLoginAt: user.lastLoginAt,
      });
    } catch (error) {
      console.error('Get profile error:', error);
      res.status(500).json({ error: 'Failed to get user profile' });
    }
  };

  // Get all users (admin only)
  getUsers = async (req: Request, res: Response): Promise<void> => {
    try {
      const page = parseInt(req.query.page as string) || 1;
      const limit = parseInt(req.query.limit as string) || 10;
      const role = req.query.role as UserRole;
      const isActive = req.query.isActive ? req.query.isActive === 'true' : undefined;

      const result = await this.userService.getUsers({
        page,
        limit,
        role,
        isActive,
      });

      res.json(result);
    } catch (error) {
      console.error('Get users error:', error);
      res.status(500).json({ error: 'Failed to get users' });
    }
  };

  // Get user by ID (admin/moderator only)
  getUserById = async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;

      if (!id) {
        res.status(400).json({ error: 'User ID is required' });
        return;
      }

      const user = await this.userService.getUserById(id);

      if (!user) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      res.json({
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        fullName: user.fullName,
        role: user.role,
        isActive: user.isActive,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt,
        lastLoginAt: user.lastLoginAt,
      });
    } catch (error) {
      console.error('Get user by ID error:', error);
      res.status(500).json({ error: 'Failed to get user' });
    }
  };

  // Create user (admin only)
  createUser = async (req: Request, res: Response): Promise<void> => {
    try {
      const userData: CreateUserDto = {
        email: req.body.email,
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        role: req.body.role || UserRole.USER,
      };

      const user = await this.userService.createUser(userData);

      res.status(201).json({
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        fullName: user.fullName,
        role: user.role,
        isActive: user.isActive,
        createdAt: user.createdAt,
      });
    } catch (error) {
      console.error('Create user error:', error);

      if (error instanceof Error && error.message === 'User with this email already exists') {
        res.status(409).json({ error: error.message });
        return;
      }

      res.status(500).json({ error: 'Failed to create user' });
    }
  };

  // Update user (admin only, or user updating their own profile)
  updateUser = async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;
      const currentUser = req.user as any;

      if (!id) {
        res.status(400).json({ error: 'User ID is required' });
        return;
      }

      // Check if user is updating their own profile or is admin
      if (currentUser.id !== id && currentUser.role !== UserRole.ADMIN) {
        res.status(403).json({ error: 'Insufficient permissions' });
        return;
      }

      const updateData: UpdateUserDto = {};

      if (req.body.firstName !== undefined) updateData.firstName = req.body.firstName;
      if (req.body.lastName !== undefined) updateData.lastName = req.body.lastName;

      // Only admins can change role and active status
      if (currentUser.role === UserRole.ADMIN) {
        if (req.body.role !== undefined) updateData.role = req.body.role;
        if (req.body.isActive !== undefined) updateData.isActive = req.body.isActive;
      }

      const user = await this.userService.updateUser(id, updateData);

      res.json({
        id: user.id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        fullName: user.fullName,
        role: user.role,
        isActive: user.isActive,
        updatedAt: user.updatedAt,
      });
    } catch (error) {
      console.error('Update user error:', error);

      if (error instanceof Error && error.message === 'User not found') {
        res.status(404).json({ error: error.message });
        return;
      }

      res.status(500).json({ error: 'Failed to update user' });
    }
  };

  // Delete user (admin only)
  deleteUser = async (req: Request, res: Response): Promise<void> => {
    try {
      const { id } = req.params;
      const currentUser = req.user as any;

      if (!id) {
        res.status(400).json({ error: 'User ID is required' });
        return;
      }

      // Prevent admin from deleting themselves
      if (currentUser.id === id) {
        res.status(400).json({ error: 'Cannot delete your own account' });
        return;
      }

      const success = await this.userService.deleteUser(id);

      if (!success) {
        res.status(404).json({ error: 'User not found' });
        return;
      }

      res.json({ success: true, message: 'User deleted successfully' });
    } catch (error) {
      console.error('Delete user error:', error);
      res.status(500).json({ error: 'Failed to delete user' });
    }
  };

  // Get user statistics (admin only)
  getUserStats = async (req: Request, res: Response): Promise<void> => {
    try {
      const stats = await this.userService.getUserStats();
      res.json(stats);
    } catch (error) {
      console.error('Get user stats error:', error);
      res.status(500).json({ error: 'Failed to get user statistics' });
    }
  };
}
