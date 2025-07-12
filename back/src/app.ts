/// <reference path="./types/express.d.ts" />
import 'reflect-metadata';
import express from 'express';
import session from 'express-session';
import connectPgSimple from 'connect-pg-simple';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import morgan from 'morgan';
import { AppDataSource } from './data-source';
// Temporarily disable auth and route imports to isolate path-to-regexp error
import { configureOIDC } from './config/auth';
import passport from './config/auth';
import { sessionSecurity } from './middleware/security';
import { createOidcDevInterceptor } from './middleware/oidc-dev-interceptor';
import { config } from './config/environment';

// Import routes
import authRoutes from './routes/auth';
import userRoutes from './routes/users';

const app: express.Express = express();
const PORT = config.port;

// Get URLs from centralized configuration
const BACKEND_URL = config.backendUrl;
const FRONTEND_URL = config.frontendUrl;
const INTERNAL_BACKEND_URL = config.internalBackendUrl;

// Session store
const pgSession = connectPgSimple(session);

// Initialize database connection
console.log('🔄 Attempting to connect to database...');
console.log('Database config:', {
  host: config.database.host,
  port: config.database.port,
  database: config.database.database,
  username: config.database.username
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
  // Build form-action CSP directive dynamically based on OIDC configuration
  function buildFormActionDirective(): string[] {
    const formActions = ["'self'", BACKEND_URL, FRONTEND_URL];

    // Add real OIDC issuer if configured (for production)
    if (config.oidc.issuer) {
      const realOidcIssuer = config.oidc.issuer;
      if (!formActions.includes(realOidcIssuer)) {
        formActions.push(realOidcIssuer);
      }
    }

    return formActions;
  }

  // Always enable CSP for better security
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https:"],
          fontSrc: ["'self'", "https://fonts.gstatic.com", "https:", "data:"],
          scriptSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", "data:", "https:"],
          formAction: buildFormActionDirective(),
          connectSrc: ["'self'", BACKEND_URL, FRONTEND_URL, INTERNAL_BACKEND_URL, "https:", "wss:"],
          frameSrc: ["'self'", "https:"],
          childSrc: ["'self'", "https:"],
        },
      },
      crossOriginEmbedderPolicy: false,
      // Enhanced security headers for production
      xFrameOptions: { action: 'deny' },
      xContentTypeOptions: true,
      xXssProtection: true,
      referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
      }
    }));

  // Basic middleware
  app.use(compression());
  app.use(morgan('combined'));

  // CORS configuration - single comprehensive setup
  app.use(cors({
    origin: function (origin, callback) {
      // Allow requests with no origin or null origin (like direct browser navigation, form submissions)
      if (!origin || origin === 'null') return callback(null, true);

      const allowedOrigins = [
        FRONTEND_URL,
        'http://localhost:42000', // Angular dev server fallback
        BACKEND_URL, // Allow same-origin requests for dev interceptor
        INTERNAL_BACKEND_URL,  // Allow internal container requests for dev interceptor
        'http://localhost:5000',  // Allow localhost requests for dev interceptor
      ].filter(Boolean);

      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      } else {
        console.log('CORS: Rejected origin:', origin);
        console.log('CORS: Allowed origins:', allowedOrigins);
        return callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'x-requested-with', 'X-Requested-With'],
    exposedHeaders: ['set-cookie'],
    optionsSuccessStatus: 200, // Some legacy browsers (IE11, various SmartTVs) choke on 204
    preflightContinue: false   // Pass control to next handler after preflight
  }));

  // Body parsing middleware
  app.use(express.json({ limit: '10mb' }));
  app.use(express.urlencoded({ extended: true, limit: '10mb' }));

  // Session configuration with enhanced security
  const encodedPassword = encodeURIComponent(config.database.password);

  app.use(session({
    store: new pgSession({
      conString: `postgresql://${config.database.username}:${encodedPassword}@${config.database.host}:${config.database.port}/${config.database.database}`,
      tableName: 'session',
      createTableIfMissing: true,
      pruneSessionInterval: 900, // in seconds : 15 minutes - prune old sessions every 15 minutes
    }),
    secret: config.session.secret,
    resave: true, // Resave session even if unmodified
    saveUninitialized: false, // Don't create sessions for unauthenticated users
    rolling: true, // Reset expiration on activity (sliding session)
    cookie: {
      secure: true, // HTTPS only
      httpOnly: true, // Prevent XSS attacks by blocking JavaScript access
      maxAge: config.session.rollingMinutes * 60 * 1000, // Rolling session duration (resets on activity)
      sameSite: config.isDevelopment
        ? 'none' // Allow cross-origin in development (front.localhost <-> node.localhost)
        : 'strict', // Strong CSRF protection in production (same domain)
      path: '/', // Cookie available for all app paths
      domain: config.isDevelopment ? undefined : config.session.cookieDomain, // Explicit domain in production
    },
    name: config.isDevelopment
      ? 'connect.sid' // Default name for development
      : config.session.cookieName || 'app_session', // Custom name in production
    proxy: true, // Trust proxy headers from Traefik
  }));

  // Passport middleware
  app.use(passport.session()); // Use session middleware with pauseStream option

  // Session security middleware - enforces JWT token expiration
  app.use(sessionSecurity);

  // OIDC Dev Interceptor - MUST be registered BEFORE auth routes and Passport config
  // This intercepts OIDC provider calls when DEV_BYPASS_AUTH=true in development
  if (config.isDevelopment && config.dev.bypassAuth) {
    console.log('🔧 Registering OIDC dev interceptor...');
    app.use(createOidcDevInterceptor());
    console.log('✅ OIDC dev interceptor registered');
  }

  // Debug middleware - simplified auth logging
  if (config.isDevelopment) {
    app.use((req, res, next) => {
      // Only log auth-related requests to reduce noise
      if (req.path.startsWith('/api/auth')) {
        console.log(`\n=== ${req.method} ${req.path} ===`);
        console.log('User authenticated:', req.isAuthenticated());
        console.log('================================\n');
      }
      next();
    });
  }

  // Health check endpoint
  app.get('/health', (req, res) => {
    res.json({
      status: 'ok',
      message: 'Server is running',
      timestamp: new Date().toISOString(),
      environment: config.nodeEnv,
    });
  });

  // API routes
  app.use('/api/auth', authRoutes);
  app.use('/api/users', userRoutes);

  // OIDC Dev Interceptor (for development)
  if (config.isDevelopment) {
    if (config.dev.bypassAuth) {
      // Default to dev interceptor in development (unless explicitly disabled)
      console.log('🔧 Using OIDC dev interceptor (default for development)');
      // Dev interceptor is already registered above
    } else {
      console.log('⚠️  DEV_BYPASS_AUTH=false: No development OIDC configured. Set DEV_BYPASS_AUTH=true to enable dev interceptor');
    }
  }

  // Configure OIDC after routes are registered to ensure mock routes are available
  setTimeout(async () => {
    try {
      await configureOIDC();
    } catch (error) {
      console.error('❌ Failed to configure OIDC:', error);
    }
  }, 1000); // Wait 1 second for routes to be fully registered

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
      error: config.isProduction ? 'Internal Server Error' : err.message,
      ...(config.isDevelopment && { stack: err.stack }),
    });
  });

  // Start server
  app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📱 Environment: ${config.nodeEnv}`);
    console.log(`🔗 Health check: ${BACKEND_URL}/health`);
  });
} // End of setupApp function

export default app;
