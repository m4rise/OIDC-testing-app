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
import mockOidcRoutes from './routes/mock-oidc';

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
const isDevelopment = process.env.NODE_ENV === 'development';
const disableCSP = process.env.DISABLE_CSP === 'true';

if (disableCSP && isDevelopment) {
  console.log('⚠️  CSP disabled for development');
  app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false,
  }));
} else {
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https:"],
        fontSrc: ["'self'", "https://fonts.gstatic.com", "https:", "data:"],
        scriptSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", "data:", "https:"],
        formAction: ["'self'", "'unsafe-inline'"],
        connectSrc: ["'self'", "https://node.localhost", "https://front.localhost", "https:", "wss:"],
        frameSrc: ["'self'", "https:"],
        childSrc: ["'self'", "https:"],
      },
    },
    crossOriginEmbedderPolicy: false,
  }));
}

// Basic middleware
app.use(compression());
app.use(morgan('combined'));

// Custom CORS middleware to ensure proper headers for credentials
app.use((req, res, next) => {
  const origin = req.headers.origin;
  const allowedOrigins = [
    'https://front.localhost',
    'http://front.localhost',
    'https://node.localhost', // Allow same-origin requests for mock OIDC
    'http://node.localhost',
    process.env.FRONTEND_URL
  ].filter(Boolean);

  // Set CORS headers
  if (origin && allowedOrigins.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin);
  } else if (!origin || origin === 'null') {
    // For requests without origin or null origin (direct browser navigation, form submissions)
    res.header('Access-Control-Allow-Origin', '*');
  }

  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  res.header('Access-Control-Expose-Headers', 'Set-Cookie');

  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  next();
});

// CORS configuration (backup)
app.use(cors({
  origin: function (origin, callback) {
    // Allow requests with no origin or null origin (like direct browser navigation, form submissions)
    if (!origin || origin === 'null') return callback(null, true);

    const allowedOrigins = [
      'https://front.localhost',
      'http://front.localhost',
      'https://node.localhost', // Allow same-origin requests for mock OIDC
      'http://node.localhost',
      process.env.FRONTEND_URL
    ].filter(Boolean);

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      console.log('CORS: Rejected origin:', origin);
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-requested-with', 'X-Requested-With'],
  exposedHeaders: ['set-cookie'],
  optionsSuccessStatus: 200 // Some legacy browsers (IE11, various SmartTVs) choke on 204
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
  saveUninitialized: false, // Create sessions immediately for better debugging
  rolling: false, // Don't reset expiration on every request
  cookie: {
    secure: true, // Set to true since we're using HTTPS through Traefik
    httpOnly: false, // Set to false temporarily for debugging - we can see cookies in browser dev tools
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'none', // Use 'none' for cross-origin requests with secure=true
    path: '/', // Ensure cookie is available for all paths
    // Remove domain to let browser handle it naturally
  },
  name: 'connect.sid', // Use default session cookie name for better compatibility
  proxy: true, // Trust proxy headers from Traefik
}));

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Debug middleware - log session info for troubleshooting
if (process.env.NODE_ENV === 'development') {
  app.use((req, res, next) => {
    // Log all requests, not just auth-related ones, to see cookie behavior
    console.log(`\n=== ${req.method} ${req.path} ===`);
    console.log('Origin:', req.get('origin') || 'none');
    console.log('Host:', req.get('host') || 'none');
    console.log('Session ID:', req.sessionID);
    console.log('User authenticated:', req.isAuthenticated());
    console.log('User:', req.user ? `${req.user.email} (${req.user.role})` : 'none');
    console.log('Cookie header:', req.get('cookie') || 'none');
    console.log('Set-Cookie will be sent:', res.get('set-cookie') || 'none');

    // Intercept response to log set-cookie headers
    const originalSetHeader = res.setHeader;
    res.setHeader = function(name, value) {
      if (name.toLowerCase() === 'set-cookie') {
        console.log('🍪 Setting cookie:', value);
      }
      return originalSetHeader.call(this, name, value);
    };

    // Intercept session saving
    const originalSave = req.session.save;
    req.session.save = function(callback) {
      console.log('💾 Saving session:', req.sessionID);
      return originalSave.call(this, callback);
    };

    console.log('================================\n');
    next();
  });
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    message: 'Server is running',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
  });
});

// Test endpoint for cookie debugging
app.get('/api/test-session', (req, res) => {
  console.log('\n=== TEST SESSION ENDPOINT ===');
  console.log('Session ID:', req.sessionID);
  console.log('Cookie header:', req.get('cookie') || 'none');
  console.log('User agent:', req.get('user-agent'));
  console.log('Origin:', req.get('origin') || 'none');

  // Force session data
  (req.session as any).testData = 'Browser cookie test at ' + new Date().toISOString();

  res.json({
    sessionId: req.sessionID,
    testData: (req.session as any).testData,
    cookieReceived: !!req.get('cookie'),
    sessionData: req.session
  });
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

// Mock OIDC routes (for development)
if (process.env.NODE_ENV === 'development') {
  app.use('/api/mock-oidc', mockOidcRoutes);
  console.log('🎭 Mock OIDC routes enabled at /api/mock-oidc');
}

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
  console.log(`🔗 Health check: https://node.localhost/health`);
});

} // End of setupApp function

export default app;
