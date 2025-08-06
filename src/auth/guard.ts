import type { Request, Response, NextFunction } from 'express';
import { getSession } from '@auth/express';
import { authConfig } from './index.js';

declare global {
  namespace Express {
    // noinspection JSUnusedGlobalSymbols
    interface Request {
      /**
       * The Auth.js session object retrieved by getSession(), including user
       * info and tokens. Set by requireAuth guard upon successful auth.
       */
      authSession?: Awaited<ReturnType<typeof getSession>>;
    }
  }
}

/**
 * Middleware that ensures the user is authenticated before accessing
 * protected routes. It retrieves the current Auth.js session via
 * getSession() and validates that a user is present. If authentication
 * fails, the client is redirected to the sign-in page with the original
 * URL preserved in the callbackUrl query parameter. On success, the
 * session is attached to req.authSession and control is passed to the
 * next handler.
 *
 * @param req  - Express Request; the session will be available at
 *               req.authSession after validation.
 * @param res  - Express Response; used to send redirects for
 *               unauthenticated requests.
 * @param next - Express NextFunction; invoked to pass control on
 *               success or errors.
 *
 * @remarks
 * - Must be used after ExpressAuth(authConfig) middleware so that
 *   request cookies and body are parsed.
 * - Relies on getSession(req, authConfig) from @auth/express.
 * - Redirects unauthenticated users to
 *   `/auth/signin?callbackUrl=<original URL>`.
 * - Original request URL is URL-encoded in callbackUrl.
 *
 * @example
 * ```ts
 * import { requireAuth } from './guards'
 *
 * app.get('/profile', requireAuth, (req, res) => {
 *   res.render('profile', { user: req.authSession!.user })
 * })
 * ```
 */
export async function requireAuth(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  try {
    const session = await getSession(req, authConfig);
    if (!session?.user) {
      const callbackUrl = encodeURIComponent(req.originalUrl);
      return res.redirect(`/auth/signin?callbackUrl=${callbackUrl}`);
    }
    req.authSession = session;
    next();
  } catch (err) {
    next(err as Error);
  }
}
