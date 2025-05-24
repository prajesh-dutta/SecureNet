import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as LocalStrategy } from 'passport-local';
import bcrypt from 'bcryptjs';
import { Express, Request, Response, NextFunction } from 'express';
import session from 'express-session';
import { storage } from './storage';

// Configure passport
export function setupAuth(app: Express) {
  // Session setup
  app.use(
    session({
      secret: process.env.SESSION_SECRET || 'securenet-secret',
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
      },
    })
  );

  // Initialize passport
  app.use(passport.initialize());
  app.use(passport.session());

  // Serialize and deserialize user
  passport.serializeUser((user: any, done) => {
    done(null, user.id);
  });

  passport.deserializeUser(async (id: number, done) => {
    try {
      const user = await storage.getUser(id);
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  });

  // Local strategy for email/password login
  passport.use(
    new LocalStrategy(
      {
        usernameField: 'email',
        passwordField: 'password',
      },
      async (email, password, done) => {
        try {
          // Find user by email
          const user = await storage.getUserByEmail(email);
          
          // If user doesn't exist
          if (!user) {
            return done(null, false, { message: 'Incorrect email or password' });
          }
          
          // Check password
          const isMatch = await bcrypt.compare(password, user.password);
          if (!isMatch) {
            return done(null, false, { message: 'Incorrect email or password' });
          }
          
          // Update last login time
          await storage.updateLastLogin(user.id);
          
          return done(null, user);
        } catch (error) {
          return done(error);
        }
      }
    )
  );

  // Google OAuth strategy
  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(
      new GoogleStrategy(
        {
          clientID: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          callbackURL: '/api/auth/google/callback',
          scope: ['profile', 'email'],
        },
        async (accessToken, refreshToken, profile, done) => {
          try {
            // Check if user already exists
            const email = profile.emails?.[0]?.value;
            if (!email) {
              return done(new Error('Email not provided by Google'), null);
            }
            
            let user = await storage.getUserByEmail(email);
            
            // If user doesn't exist, create a new one
            if (!user) {
              user = await storage.createUser({
                username: email.split('@')[0],
                email: email,
                password: await bcrypt.hash(Math.random().toString(36).slice(-8), 10),
                role: 'user',
                lastLogin: new Date()
              });
            } else {
              // Update last login time
              await storage.updateLastLogin(user.id);
            }
            
            return done(null, user);
          } catch (error) {
            return done(error, null);
          }
        }
      )
    );
  }

  // Authentication middleware
  app.use((req, res, next) => {
    // Add isAuthenticated to res.locals for views
    res.locals.isAuthenticated = req.isAuthenticated();
    res.locals.user = req.user;
    next();
  });

  // Auth routes
  setupAuthRoutes(app);
}

// Authentication routes
function setupAuthRoutes(app: Express) {
  // Local auth routes
  app.post('/api/auth/signup', async (req: Request, res: Response, next: NextFunction) => {
    try {
      const { username, email, password } = req.body;
      
      // Check if email already exists
      const existingUser = await storage.getUserByEmail(email);
      if (existingUser) {
        return res.status(400).json({ message: 'Email already in use' });
      }
      
      // Hash password
      const hashedPassword = await bcrypt.hash(password, 10);
      
      // Create new user
      const user = await storage.createUser({
        username,
        email,
        password: hashedPassword,
        role: 'user',
        lastLogin: new Date()
      });
      
      // Log in the new user
      req.login(user, (err) => {
        if (err) {
          return next(err);
        }
        return res.status(201).json({ user: { id: user.id, username: user.username, email: user.email } });
      });
    } catch (error) {
      return res.status(500).json({ message: 'Error creating user', error });
    }
  });

  app.post('/api/auth/login', (req: Request, res: Response, next: NextFunction) => {
    passport.authenticate('local', (err, user, info) => {
      if (err) {
        return next(err);
      }
      if (!user) {
        return res.status(401).json({ message: info.message });
      }
      req.login(user, (err) => {
        if (err) {
          return next(err);
        }
        return res.json({ user: { id: user.id, username: user.username, email: user.email } });
      });
    })(req, res, next);
  });

  // Google OAuth routes
  app.get('/api/auth/google', passport.authenticate('google'));

  app.get(
    '/api/auth/google/callback',
    passport.authenticate('google', {
      failureRedirect: '/login',
      successRedirect: '/dashboard',
    })
  );

  // Logout route
  app.post('/api/auth/logout', (req: Request, res: Response) => {
    req.logout((err) => {
      if (err) {
        return res.status(500).json({ message: 'Error logging out', error: err });
      }
      res.json({ message: 'Logged out successfully' });
    });
  });

  // Get current user
  app.get('/api/auth/user', (req: Request, res: Response) => {
    if (req.isAuthenticated()) {
      const user = req.user as any;
      return res.json({
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      });
    }
    return res.status(401).json({ message: 'Not authenticated' });
  });
}

// Authentication middleware for protected routes
export function isAuthenticated(req: Request, res: Response, next: NextFunction) {
  if (req.isAuthenticated()) {
    return next();
  }
  
  // For API routes, return 401
  if (req.path.startsWith('/api/')) {
    return res.status(401).json({ message: 'Authentication required' });
  }
  
  // For page routes, redirect to login
  return res.redirect('/login');
}