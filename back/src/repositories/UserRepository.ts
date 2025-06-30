import { Repository } from 'typeorm';
import { AppDataSource } from '../data-source';
import { User, UserRole } from '../entities/User';

export class UserRepository {
  private repository: Repository<User>;

  constructor() {
    this.repository = AppDataSource.getRepository(User);
  }

  async findById(id: string): Promise<User | null> {
    return await this.repository.findOne({ where: { id } });
  }

  async findByEmail(email: string): Promise<User | null> {
    return await this.repository.findOne({ where: { email } });
  }

  async findByNni(nni: string): Promise<User | null> {
    return await this.repository.findOne({ where: { nni } });
  }

  async findAll(options?: {
    skip?: number;
    take?: number;
    role?: UserRole;
    isActive?: boolean;
  }): Promise<[User[], number]> {
    const query = this.repository.createQueryBuilder('user');

    if (options?.role) {
      query.andWhere('user.role = :role', { role: options.role });
    }

    if (options?.isActive !== undefined) {
      query.andWhere('user.isActive = :isActive', { isActive: options.isActive });
    }

    if (options?.skip) {
      query.skip(options.skip);
    }

    if (options?.take) {
      query.take(options.take);
    }

    query.orderBy('user.createdAt', 'DESC');

    return await query.getManyAndCount();
  }

  async create(userData: Partial<User>): Promise<User> {
    const user = this.repository.create(userData);
    return await this.repository.save(user);
  }

  async update(id: string, userData: Partial<User>): Promise<User | null> {
    await this.repository.update(id, userData);
    return await this.findById(id);
  }

  async delete(id: string): Promise<boolean> {
    const result = await this.repository.delete(id);
    return (result.affected ?? 0) > 0;
  }

  async deactivate(id: string): Promise<User | null> {
    return await this.update(id, { isActive: false });
  }

  async activate(id: string): Promise<User | null> {
    return await this.update(id, { isActive: true });
  }

  async updateLastLogin(id: string): Promise<void> {
    await this.repository.update(id, { lastLoginAt: new Date() });
  }

  async count(): Promise<number> {
    return await this.repository.count();
  }

  async countByRole(role: UserRole): Promise<number> {
    return await this.repository.count({ where: { role } });
  }
}
