import { NextFunction, Request, Response, Router } from 'express';
import session from 'express-session';
import passport from 'passport';
import * as oidc from 'openid-client';
import { Strategy as OpenIDConnectStrategy } from 'openid-client/passport';
import { ZitadelUser } from './types.js';
import { randomUUID } from 'node:crypto';

export type AuthReq = Request & { user?: ZitadelUser };

export interface ZitadelConfig {
  domain: string;
  clientId: string;
  clientSecret: string;
  callbackURL: string;
  sessionSecret: string;
  sessionDuration: number;
  nodeEnv?: string;
  postLogoutURL?: string;
  postLoginURL?: string;
}

/**
 * Middleware that allows the request through only if the session is
 * authenticated; otherwise redirects the browser to the login route.
 */
export function ensureAuth(req: AuthReq, res: Response, next: NextFunction) {
  return req.isAuthenticated() ? next() : res.redirect('/auth/login');
}

/**
 * Creates and configures the Zitadel authentication middleware
 */
export async function createZitadelMiddleware(config?: Partial<ZitadelConfig>) {
  const zitadelConfig: ZitadelConfig = {
    domain: config?.domain || process.env.ZITADEL_DOMAIN!,
    clientId: config?.clientId || process.env.ZITADEL_CLIENT_ID!,
    clientSecret: config?.clientSecret || process.env.ZITADEL_CLIENT_SECRET!,
    callbackURL: config?.callbackURL || process.env.ZITADEL_CALLBACK_URL!,
    postLogoutURL:
      config?.postLogoutURL || process.env.ZITADEL_POST_LOGOUT_URL!,
    postLoginURL: config?.postLoginURL || process.env.ZITADEL_POST_LOGIN_URL!,
    sessionSecret: config?.sessionSecret || process.env.SESSION_SECRET!,
    sessionDuration:
      config?.sessionDuration || Number(process.env.SESSION_DURATION || '3600'),
    nodeEnv: config?.nodeEnv || process.env.NODE_ENV,
  };

  const oidcConfig = await oidc.discovery(
    new URL(zitadelConfig.domain),
    zitadelConfig.clientId,
    zitadelConfig.clientSecret,
  );

  const strategy = new OpenIDConnectStrategy(
    {
      config: oidcConfig,
      name: 'zitadel',
      scope: 'openid profile email',
      callbackURL: zitadelConfig.callbackURL,
    },
    (
      tokenSet: oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers,
      done: passport.AuthenticateCallback,
    ): void => {
      const claims = tokenSet.claims()!;

      done(null, {
        id: claims.sub,
        email: (claims.email as string) ?? '',
        name: (claims.name as string) ?? '',
        preferred_username: (claims.preferred_username as string) ?? '',
      } satisfies ZitadelUser);
    },
  );

  passport.use(strategy);

  const router = Router();
  router.use(
    session({
      secret: zitadelConfig.sessionSecret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        httpOnly: true,
        secure: zitadelConfig.nodeEnv === 'production',
        maxAge: zitadelConfig.sessionDuration * 1000,
      },
    }),
  );
  router.use(passport.authenticate('session'));

  passport.serializeUser<ZitadelUser>((user, done) => done(null, user));
  passport.deserializeUser<ZitadelUser>((obj, done) => done(null, obj));

  /**
   * GET /auth/login — initiates the Authorisation Code + PKCE flow by
   * redirecting the browser to ZITADEL's `/authorize` endpoint.
   */
  router.get(
    '/auth/login',
    (req: AuthReq, res: Response, next: NextFunction) => {
      passport.authenticate('zitadel')(req, res, next);
    },
  );

  /**
   * GET /auth/callback — receives the `code` from ZITADEL, exchanges it for
   * tokens, initializes the session, and finally redirects to /profile or
   * /auth/error depending on an outcome.
   */
  router.get(
    '/auth/callback',
    (req: AuthReq, res: Response, next: NextFunction) => {
      passport.authenticate('zitadel', {
        failureRedirect: '/auth/error',
        successRedirect: zitadelConfig.postLoginURL || '/profile',
      })(req, res, next);
    },
  );

  /**
   * GET /auth/logout — destroys the session then redirects to the landing
   * page. Errors in `req.logout` propagate to Express error middleware.
   */
  router.get(
    '/auth/logout',
    (req: AuthReq, res: Response, _next: NextFunction) => {
      req.logout(() => {
        res.redirect(
          oidc
            .buildEndSessionUrl(oidcConfig, {
              post_logout_redirect_uri:
                zitadelConfig.postLogoutURL || `${req.protocol}://${req.host}`,
              state: randomUUID(),
            })
            .toString(),
        );
      });
    },
  );

  /**
   * GET /auth/error — simple JSON error stub when authentication fails or
   * the user cancels the login consent screen.
   */
  router.get(
    '/auth/error',
    (_req: AuthReq, res: Response, _next: NextFunction) => {
      res.status(401).json({ error: 'Authentication failed' });
    },
  );

  return router;
}
