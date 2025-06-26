import passport from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';
import { AppDataSource } from '../data-source';
import { User, UserRole } from '../entities/User';

export interface MockUser {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  role: UserRole;
  sub: string;
}

// Mock users for development (using UUID format for compatibility with database)
const mockUsers: MockUser[] = [
  {
    id: '550e8400-e29b-41d4-a716-446655440001',
    email: 'admin@example.com',
    firstName: 'Admin',
    lastName: 'User',
    role: UserRole.ADMIN,
    sub: 'mock-admin-123'
  },
  {
    id: '550e8400-e29b-41d4-a716-446655440002',
    email: 'user@example.com',
    firstName: 'Regular',
    lastName: 'User',
    role: UserRole.USER,
    sub: 'mock-user-456'
  },
  {
    id: '550e8400-e29b-41d4-a716-446655440003',
    email: 'manager@example.com',
    firstName: 'Manager',
    lastName: 'User',
    role: UserRole.USER,
    sub: 'mock-manager-789'
  }
];

export const configureMockOIDC = () => {
  console.log('🎭 Configuring Mock OIDC strategy for development');

  // Mock OIDC strategy using a custom approach
  passport.use('mock-oidc', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'mockAuth', // We'll use this to bypass password checking
    passReqToCallback: true
  }, async (req: any, email: string, mockAuth: string, done: Function) => {
    try {
      const userRepository = AppDataSource.getRepository(User);

      // Get userInfo from request if available (from callback), otherwise find by email
      const userInfo = req.body?.userInfo;
      let mockUser;

      if (userInfo) {
        // Use the userInfo passed from the callback (contains the selected user's role)
        mockUser = {
          email: userInfo.email,
          firstName: userInfo.given_name,
          lastName: userInfo.family_name,
          sub: userInfo.sub,
          role: userInfo.role
        };
      } else {
        // Fallback: find mock user by email
        mockUser = mockUsers.find(u => u.email === email);
      }

      if (!mockUser) {
        return done(null, false, { message: 'Mock user not found' });
      }

      // Try to find existing user in database
      let user = await userRepository.findOne({
        where: { email: mockUser.email }
      });

      console.log('🎭 Mock Auth - Processing user:', {
        email: mockUser.email,
        role: mockUser.role,
        existingUser: !!user
      });

      if (!user) {
        // Create new user from mock data
        const mockIssuer = process.env.MOCK_OIDC_ISSUER || 'https://node.localhost/api/mock-oidc';
        user = userRepository.create({
          email: mockUser.email,
          firstName: mockUser.firstName,
          lastName: mockUser.lastName,
          oidcSubject: mockUser.sub,
          oidcIssuer: mockIssuer,
          oidcProfile: {
            sub: mockUser.sub,
            email: mockUser.email,
            given_name: mockUser.firstName,
            family_name: mockUser.lastName,
            name: `${mockUser.firstName} ${mockUser.lastName}`,
            mock: true
          },
          role: mockUser.role,
          isActive: true,
        });
      } else {
        // Update existing user
        const mockIssuer = process.env.MOCK_OIDC_ISSUER || 'https://node.localhost/api/mock-oidc';
        user.oidcSubject = mockUser.sub;
        user.oidcIssuer = mockIssuer;
        user.oidcProfile = {
          sub: mockUser.sub,
          email: mockUser.email,
          given_name: mockUser.firstName,
          family_name: mockUser.lastName,
          name: `${mockUser.firstName} ${mockUser.lastName}`,
          mock: true
        };
        user.role = mockUser.role;
        user.lastLoginAt = new Date();
      }

      await userRepository.save(user);
      console.log('🎭 Mock user authenticated:', {
        id: user.id,
        email: user.email,
        role: user.role,
        isActive: user.isActive
      });
      return done(null, user);
    } catch (error) {
      console.error('Mock OIDC authentication error:', error);
      return done(error, null);
    }
  }));

  // Serialize user for session
  passport.serializeUser((user: any, done) => {
    done(null, user.id);
  });

  // Deserialize user from session
  passport.deserializeUser(async (id: string, done) => {
    try {
      // Check if this is a mock user ID first (for development)
      const mockUser = mockUsers.find(u => u.id === id);
      if (mockUser) {
        // Return mock user with database-compatible structure
        const userForSession = {
          ...mockUser,
          isActive: true,
          createdAt: new Date(),
          updatedAt: new Date(),
          lastLoginAt: new Date(),
          hasPermission: () => true // Mock permission check
        };
        return done(null, userForSession);
      }

      // Otherwise, look up real user in database
      const userRepository = AppDataSource.getRepository(User);
      const user = await userRepository.findOne({ where: { id } });
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  });
};

export { mockUsers };
