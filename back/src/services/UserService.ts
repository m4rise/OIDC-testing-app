import { UserRepository } from '../repositories/UserRepository';
import { User, UserRole } from '../entities/User';

export interface CreateUserDto {
  email: string;
  firstName: string;
  lastName: string;
  role?: UserRole;
}

export interface UpdateUserDto {
  firstName?: string;
  lastName?: string;
  role?: UserRole;
  isActive?: boolean;
}

export interface UserListOptions {
  page?: number;
  limit?: number;
  role?: UserRole;
  isActive?: boolean;
}

export interface PaginatedUsers {
  users: User[];
  total: number;
  page: number;
  limit: number;
  totalPages: number;
}

export class UserService {
  private userRepository: UserRepository;

  constructor() {
    this.userRepository = new UserRepository();
  }

  async getUserById(id: string): Promise<User | null> {
    return await this.userRepository.findById(id);
  }

  async getUserByEmail(email: string): Promise<User | null> {
    return await this.userRepository.findByEmail(email);
  }

  async getUsers(options: UserListOptions = {}): Promise<PaginatedUsers> {
    const { page = 1, limit = 10, role, isActive } = options;
    const skip = (page - 1) * limit;

    const [users, total] = await this.userRepository.findAll({
      skip,
      take: limit,
      role,
      isActive,
    });

    const totalPages = Math.ceil(total / limit);

    return {
      users,
      total,
      page,
      limit,
      totalPages,
    };
  }

  async createUser(userData: CreateUserDto): Promise<User> {
    // Check if user already exists
    const existingUser = await this.userRepository.findByEmail(userData.email);
    if (existingUser) {
      throw new Error('User with this email already exists');
    }

    return await this.userRepository.create({
      ...userData,
      role: userData.role || UserRole.USER,
      isActive: true,
    });
  }

  async updateUser(id: string, userData: UpdateUserDto): Promise<User> {
    const existingUser = await this.userRepository.findById(id);
    if (!existingUser) {
      throw new Error('User not found');
    }

    const updatedUser = await this.userRepository.update(id, userData);
    if (!updatedUser) {
      throw new Error('Failed to update user');
    }

    return updatedUser;
  }

  async deleteUser(id: string): Promise<boolean> {
    const existingUser = await this.userRepository.findById(id);
    if (!existingUser) {
      throw new Error('User not found');
    }

    return await this.userRepository.delete(id);
  }



  async getUserStats(): Promise<{
    total: number;
    byRole: Record<UserRole, number>;
    active: number;
    inactive: number;
  }> {
    const total = await this.userRepository.count();

    // Count by role using repository queries
    const adminCount = await this.userRepository.findAll({ role: UserRole.ADMIN });
    const moderatorCount = await this.userRepository.findAll({ role: UserRole.MODERATOR });
    const userCount = await this.userRepository.findAll({ role: UserRole.USER });

    const [, activeCount] = await this.userRepository.findAll({ isActive: true });
    const [, inactiveCount] = await this.userRepository.findAll({ isActive: false });

    return {
      total,
      byRole: {
        [UserRole.ADMIN]: adminCount[1],
        [UserRole.MODERATOR]: moderatorCount[1],
        [UserRole.USER]: userCount[1],
      },
      active: activeCount,
      inactive: inactiveCount,
    };
  }
}
