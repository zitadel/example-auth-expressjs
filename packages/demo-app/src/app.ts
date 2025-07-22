import express, { Application, NextFunction, Request, Response } from 'express';
import session from 'express-session';
import passport from 'passport';

import { ZitadelStrategy, ZitadelUser } from 'passport-zitadel';
import config from './config.js';
import { dirname, join } from 'knip/dist/util/path.js';
import * as exphbs from 'express-handlebars';
import { fileURLToPath } from 'node:url';

const ensureAuth = (req: Request, res: Response, next: NextFunction) => {
  return req.isAuthenticated() ? next() : res.redirect('/auth/login');
};

export async function build(): Promise<Application> {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const app: Application = express();
  app.engine(
    'hbs',
    exphbs.engine({
      extname: '.hbs',
      defaultLayout: 'main',
      layoutsDir: join(__dirname, '..', 'res'),
      partialsDir: join(__dirname, '..', 'res', 'partials'),
    }),
  );
  app.set('view engine', 'hbs');
  app.set('views', join(__dirname, '..', 'res'));

  // Configure express-session, the stateful session equivalent to
  // @fastify/secure-session.
  app.use(
    session({
      secret: config.SESSION_SECRET,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: config.SESSION_COOKIE_SECURE,
        maxAge: config.SESSION_COOKIE_MAX_AGE * 1000,
        path: config.SESSION_COOKIE_PATH,
      },
    }),
  );

  // Initialize Passport and connect it to the session.
  // `passport.session()` is the equivalent of `@fastify/passport.secureSession()`.
  app.use(passport.initialize());
  app.use(passport.session());

  // Discover and configure the single Zitadel strategy, just like in the
  // Fastify app.
  const strategy = await ZitadelStrategy.discover({
    domain: config.ZITADEL_DOMAIN,
    clientId: config.ZITADEL_CLIENT_ID,
    clientSecret: config.ZITADEL_CLIENT_SECRET,
    callbackURL: config.ZITADEL_CALLBACK_URL,
    scope: 'openid profile email',
    postLogoutRedirectUrl: config.ZITADEL_POST_LOGOUT_URL,
  });

  passport.use(strategy);

  // Set up user serialization, which is required for session management. This
  // tells Passport how to store the user in the session.
  passport.serializeUser((user, done) => {
    done(null, user);
  });

  // Set up user deserialization. This tells Passport how to retrieve the
  // user from the session on subsequent requests.
  passport.deserializeUser((user, done) => {
    done(null, user as any);
  });

  // -----------------------------------------------------------------------
  // Routes (structured to match the Fastify app)
  // -----------------------------------------------------------------------

  app.get('/', (req: Request, res: Response): void => {
    res.render('index', {
      isAuthenticated: req.isAuthenticated(),
      loginUrl: '/auth/login',
    });
  });

  // The login route simply triggers the 'zitadel' authentication strategy.
  app.get('/auth/login', passport.authenticate('zitadel'));

  // The callback route handles the response from Zitadel, with redirects for
  // success and failure, managed by Passport.
  app.get(
    '/auth/callback',
    passport.authenticate('zitadel', {
      successRedirect: config.ZITADEL_POST_LOGIN_URL,
      failureRedirect: '/auth/error',
    }),
  );

  app.get('/auth/logout', (req: Request, res: Response, next: NextFunction) => {
    const user = req.user as ZitadelUser;
    req.logout((err: unknown) => {
      if (err) {
        return next(err);
      }
      req.session.destroy(() => {
        res.redirect(
          strategy.getLogoutUrl({
            id_token_hint: user?.id_token,
          }),
        );
      });
    });
  });

  app.get('/logout/callback', (_req: Request, res: Response): void => {
    res.render('loggedout', {
      //
    });
  });

  app.get('/auth/error', (_req: Request, res: Response): void => {
    res.status(401).send({ error: 'Authentication failed' });
  });

  // The protected profile route uses the ensureAuth middleware.
  app.get('/profile', ensureAuth, (req: Request, res: Response) => {
    const user = req.user as ZitadelUser;
    res.render('profile', {
      isAuthenticated: req.isAuthenticated(),
      userJson: JSON.stringify(user, null, 2),
      logoutUrl: '/auth/logout',
    });
  });

  return app;
}
