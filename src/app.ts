import express, {
  Application,
  NextFunction,
  Request,
  RequestHandler,
  Response,
} from 'express';
import session, { SessionOptions } from 'express-session';
import passport from 'passport';

import * as oidc from 'openid-client';
import {
  Strategy as OpenIDConnectStrategy,
  VerifyFunction,
} from 'openid-client/passport';
import type { TokenEndpointResponse } from 'openid-client';
import { ZitadelUser } from './types.js';
import type { JWTAccessTokenClaims } from 'oauth4webapi';

type AuthReq = Request & { user?: ZitadelUser };

const app: Application = express();

const sessionOpts: SessionOptions = {
  secret: process.env.SESSION_SECRET!,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    maxAge: Number(process.env.SESSION_DURATION!),
  },
};

app.use(session(sessionOpts));
app.use(passport.authenticate('session'));

passport.serializeUser<ZitadelUser>((user, done) => done(null, user));
passport.deserializeUser<ZitadelUser>((obj, done) => done(null, obj));

let strategyName = 'zitadel';

/**
 * Discovers tenant metadata, creates an OIDC client, and registers the
 * Passport strategy. Must be awaited before the server starts listening.
 */
export async function initializeOIDC(): Promise<void> {
  const issuer = process.env.ZITADEL_DOMAIN!;
  const clientId = process.env.ZITADEL_CLIENT_ID!;
  const clientSecret = process.env.ZITADEL_CLIENT_SECRET!;
  const callbackURL = process.env.ZITADEL_CALLBACK_URL!;

  const config = await oidc.discovery(new URL(issuer), clientId, clientSecret);

  /**
   * `verify` invoked by Passport once tokens are received. It builds a
   * `ZitadelUser` from ID‑token claims and stores it in the session via
   * `done(null, user)`.
   */
  const verify: VerifyFunction = (
    tokenSet: TokenEndpointResponse,
    done,
  ): void => {
    // eslint-disable-next-line
    const claims = (tokenSet as any).claims() as JWTAccessTokenClaims;

    const user: ZitadelUser = {
      id: claims.sub,
      email: (claims.email as string) ?? '',
      name: (claims.name as string) ?? '',
      preferred_username: (claims.preferred_username as string) ?? '',
    };

    done(null, user);
  };

  const strategy = new OpenIDConnectStrategy(
    { config, scope: 'openid profile email', callbackURL },
    verify,
  );

  strategyName = strategy.name; // typically the issuer host
  passport.use(strategy);
}

/**
 * Middleware that allows the request through only if the session is
 * authenticated; otherwise redirects the browser to the login route.
 */
const ensureAuth: RequestHandler = (
  req: AuthReq,
  res: Response,
  next: NextFunction,
) => (req.isAuthenticated() ? next() : res.redirect('/auth/login'));

/**
 * Landing page — returns a welcome message and the user object when
 * authenticated, or a minimal prompt to start the login flow.
 */
app.get('/', (req: AuthReq, res: Response): void => {
  if (req.isAuthenticated()) {
    res.json({ message: 'Welcome!', user: req.user });
  } else {
    res.json({ message: 'Please login', loginUrl: '/auth/login' });
  }
});

/**
 * GET /auth/login — initiates the Authorisation Code + PKCE flow by
 * redirecting the browser to ZITADEL's `/authorize` endpoint.
 */
app.get('/auth/login', (req, res, next) => {
  passport.authenticate(strategyName)(req, res, next);
});

/**
 * GET /auth/callback — receives the `code` from ZITADEL, exchanges it for
 * tokens, initializes the session, and finally redirects to /profile or
 * /auth/error depending on an outcome.
 */
app.get('/auth/callback', (req, res, next) => {
  passport.authenticate(strategyName, {
    failureRedirect: '/auth/error',
    successRedirect: '/profile',
  })(req, res, next);
});

/**
 * GET /profile — protected endpoint that simply echos the `ZitadelUser`
 * stored in the current session.
 */
app.get('/profile', ensureAuth, (req: AuthReq, res: Response): void => {
  res.json({ user: req.user });
});

/**
 * GET /auth/logout — destroys the session then redirects to the landing
 * page. Errors in `req.logout` propagate to Express error middleware.
 */
app.get('/auth/logout', (req: AuthReq, res: Response, next: NextFunction) => {
  req.logout((err) => (err ? next(err) : res.redirect('/')));
});

/**
 * GET /auth/error — simple JSON error stub when authentication fails or
 * the user cancels the login consent screen.
 */
app.get('/auth/error', (_req, res) => {
  res.status(401).json({ error: 'Authentication failed' });
});

export default app;
