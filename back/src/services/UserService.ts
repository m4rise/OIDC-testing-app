import { UserRepository } from '../repositories/UserRepository';
import { User } from '../entities/User';
import { Role } from '../entities/Role';
import { AppDataSource } from '../data-source';

export interface CreateUserDto {
  email: string;
  firstName: string;
  lastName: string;
}

export interface UpdateUserDto {
  firstName?: string;
  lastName?: string;
  isActive?: boolean;
}

export interface UserListOptions {
  page?: number;
  limit?: number;
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
    const { page = 1, limit = 10, isActive } = options;
    const skip = (page - 1) * limit;

    const [users, total] = await this.userRepository.findAll({
      skip,
      take: limit,
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

    // Create the user without role
    const user = await this.userRepository.create({
      ...userData,
      isActive: true,
    });

    // Assign default 'user' role using RBAC
    const roleRepository = AppDataSource.getRepository(Role);
    const defaultRole = await roleRepository.findOne({ where: { name: 'user' } });

    if (defaultRole) {
      user.assignRole(defaultRole);
      await this.userRepository.save(user);
    }

    return user;
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
    byRole: Record<string, number>;
    active: number;
    inactive: number;
  }> {
    const total = await this.userRepository.count();

    // Count by role using role repository
    const roleRepository = AppDataSource.getRepository(Role);
    const roles = await roleRepository.find();

    const byRole: Record<string, number> = {};

    // Count users for each role
    for (const role of roles) {
      const usersWithRole = await roleRepository
        .createQueryBuilder('role')
        .leftJoin('role.users', 'user')
        .where('role.id = :roleId', { roleId: role.id })
        .getCount();
      byRole[role.name] = usersWithRole;
    }

    const [, activeCount] = await this.userRepository.findAll({ isActive: true });
    const [, inactiveCount] = await this.userRepository.findAll({ isActive: false });

    return {
      total,
      byRole,
      active: activeCount,
      inactive: inactiveCount,
    };
  }
}
