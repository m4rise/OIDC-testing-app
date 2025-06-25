import 'reflect-metadata';
import express from 'express';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import dotenv from 'dotenv';
import { AppDataSource } from './data-source';
// Temporarily disable auth and route imports to isolate path-to-regexp error
import { configureOIDC } from './config/auth';
import passport from './config/auth';

// Import routes
import authRoutes from './routes/auth';
import userRoutes from './routes/users';

// Load environment variables
dotenv.config();

const app: express.Express = express();
const PORT = process.env.PORT || 5000;

// Session store
const pgSession = connectPgSimple(session);

// Initialize database connection
console.log('🔄 Attempting to connect to database...');
console.log('Database config:', {
  host: process.env.PG_HOST,
  port: process.env.PG_PORT,
  database: process.env.POSTGRES_DB,
  username: process.env.POSTGRES_USER
});

AppDataSource.initialize()
  .then(() => {
    console.log('✅ Database connection established');

    // Continue with the rest of the app setup
    setupApp();
  })
  .catch((error) => {
    console.error('❌ Database connection error:', error);
    process.exit(1);
  });

function setupApp() {

// Configure OIDC
configureOIDC();

// Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// Basic middleware
app.use(compression());
app.use(morgan('combined'));

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://front.localhost',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-requested-with'],
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Session configuration
const encodedPassword = encodeURIComponent(process.env.POSTGRES_PASSWORD || '');
app.use(session({
  store: new pgSession({
    conString: `postgresql://${process.env.POSTGRES_USER}:${encodedPassword}@${process.env.PG_HOST}:${process.env.PG_PORT}/${process.env.POSTGRES_DB}`,
    tableName: 'session',
    createTableIfMissing: true,
  }),
  secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
  },
  name: 'sessionId',
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not Found',
    message: 'The requested endpoint does not exist',
    path: req.originalUrl,
  });
});

// Global error handler
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Global error handler:', err);

  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === 'production' ? 'Internal Server Error' : err.message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack }),
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📱 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔗 Health check: http://localhost:${PORT}/health`);
});

} // End of setupApp function

export default app;
