import express, { Application, Request, Response } from 'express';
import cookieParser from 'cookie-parser';
import { ExpressAuth, getSession } from '@auth/express';
import config from './config.js';
import { getMessage } from './auth/message.js';
import { authConfig, buildLogoutUrl } from './auth/index.js';
import * as templateLang from 'express-handlebars';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';
import { requireAuth } from './auth/guard.js';

export async function build(): Promise<Application> {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const app: Application = express();
  app.engine(
    'hbs',
    templateLang.engine({
      extname: '.hbs',
      defaultLayout: 'main',
      layoutsDir: join(__dirname, '..', 'res'),
      partialsDir: join(__dirname, '..', 'res', 'partials'),
    }),
  );
  app.set('view engine', 'hbs');
  app.set('views', join(__dirname, '..', 'res'));
  app.use(
    '/static',
    express.static(join(__dirname, '..', 'public'), {
      maxAge: '1d',
      index: false,
    }),
  );
  app.use(cookieParser());

  /**
   * Initiates the logout process by redirecting the user to the external Identity
   * Provider's (IdP) logout endpoint. This endpoint validates that the user has an
   * active session with a valid ID token, generates a cryptographically secure state
   * parameter for CSRF protection, and stores it in a secure HTTP-only cookie.
   *
   * The state parameter will be validated upon the user's return from the IdP to
   * ensure the logout callback is legitimate and not a forged request.
   *
   * @returns A redirect response to the IdP's logout URL on success, or a 400-error
   * response if no valid session exists. The response includes a secure state cookie
   * that will be validated in the logout callback.
   */
  app.post('/auth/logout', async (req: Request, res: Response) => {
    const session = await getSession(req, authConfig);

    if (!session?.idToken) {
      res.status(400).json({ error: 'No valid session or ID token found' });
    } else {
      const { url, state } = await buildLogoutUrl(session.idToken);
      res.cookie('logout_state', state, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/auth/logout/callback',
      });
      res.redirect(url);
    }
  });

  /**
   * Handles the callback from an external Identity Provider (IdP) after a user
   * signs out. This endpoint is responsible for validating the logout request to
   * prevent Cross-Site Request Forgery (CSRF) attacks by comparing a `state`
   * parameter from the URL with a value stored in a secure, server-side cookie.
   * If validation is successful, it clears the user's session cookies and
   * redirects to a success page. Otherwise, it redirects to an error page.
   *
   * @param request - The incoming Next.js request object, which contains the
   * URL and its search parameters, including the `state` from the IdP.
   * @returns A NextResponse object that either redirects the user to a success
   * or error page. Upon success, it includes headers to delete session cookies.
   */
  app.get('/auth/logout/callback', async (req: Request, res: Response) => {
    const state = req.query.state;
    const logoutStateCookie = req.cookies['logout_state'];

    if (state && logoutStateCookie && state === logoutStateCookie) {
      res.setHeader('Clear-Site-Data', '"cookies"');
      res.redirect('/auth/logout/success');
    } else {
      const reason = encodeURIComponent('Invalid or missing state parameter.');
      res.redirect(`/auth/logout/error?reason=${reason}`);
    }
  });

  /**
   * GET /auth/signin
   *
   * Renders a custom sign-in page that displays available authentication providers
   * and handles authentication errors with user-friendly messaging. This page is
   * shown when users need to authenticate, either by visiting directly or after
   * being redirected from protected routes via the requireAuth middleware.
   *
   * The sign-in page provides a branded authentication experience that matches the
   * application's design system, rather than using Auth.js default pages. It
   * supports error display, callback URL preservation, and CSRF protection via
   * client-side JavaScript.
   *
   * Authentication flow:
   * 1. User visits protected route without session
   * 2. requireAuth redirects to /auth/signin?callbackUrl=<original-url>
   * 3. This route renders custom sign-in page with available providers
   * 4. User selects provider, CSRF token is fetched and added via JavaScript
   * 5. Form submits to /auth/signin/[provider] to initiate OAuth flow
   * 6. After successful authentication, user is redirected to callbackUrl
   *
   * Error handling supports all Auth.js error types including AccessDenied,
   * Configuration, OAuthCallback, and others, displaying contextual messages
   * via the getMessage utility function.
   *
   * The page specifically looks for the 'zitadel' provider to match the Svelte
   * implementation behavior, showing only that provider's sign-in option even
   * if multiple providers are configured.
   *
   * @param req - Express Request object containing query parameters:
   *              - callbackUrl: URL to redirect after successful authentication
   *              - error: Auth.js error code for display (optional)
   * @param res - Express Response object used to render the sign-in template
   */
  /**
   * GET /auth/signin
   *
   * Renders a custom sign-in page that displays available authentication providers
   * and handles authentication errors with user-friendly messaging. This page is
   * shown when users need to authenticate, either by visiting directly or after
   * being redirected from protected routes via the requireAuth middleware.
   *
   * The sign-in page provides a branded authentication experience that matches the
   * application's design system, rather than using Auth.js default pages. It
   * supports error display, callback URL preservation, and CSRF protection via
   * client-side JavaScript.
   *
   * Authentication flow:
   * 1. User visits protected route without session
   * 2. requireAuth redirects to /auth/signin?callbackUrl=<original-url>
   * 3. This route renders custom sign-in page with available providers
   * 4. User selects provider, CSRF token is fetched and added via JavaScript
   * 5. Form submits to /auth/signin/[provider] to initiate OAuth flow
   * 6. After successful authentication, user is redirected to callbackUrl
   *
   * Error handling supports all Auth.js error types including AccessDenied,
   * Configuration, OAuthCallback, and others, displaying contextual messages
   * via the getMessage utility function.
   *
   * The page specifically looks for the 'zitadel' provider to match the Svelte
   * implementation behavior, showing only that provider's sign-in option even
   * if multiple providers are configured.
   *
   * @param req - Express Request object containing query parameters:
   *              - callbackUrl: URL to redirect after successful authentication
   *              - error: Auth.js error code for display (optional)
   * @param res - Express Response object used to render the sign-in template
   */
  app.get('/auth/signin', async (req: Request, res: Response) => {
    const callbackUrl = req.query.callbackUrl;
    const error = req.query.error;

    res.render('auth/signin', {
      providers: authConfig.providers.map((provider) => {
        const config = typeof provider === 'function' ? provider() : provider;
        return {
          id: config.id,
          name: config.name,
          signinUrl: `/auth/signin/${config.id}`,
        };
      }),
      callbackUrl,
      message: getMessage(error, 'signin-error'),
    });
  });

  /**
   * GET /auth/error
   *
   * Intercepts authentication-related errors (e.g. AccessDenied, Configuration,
   * Verification) from sign-in or callback flows and shows a friendly error page.
   *
   * @param req  - The Express request.  May have `req.query.error` set to an
   *                 error code string.
   * @param res  - The Express response.  Renders `auth/error.hbs` with a
   *                 `{ heading, message }` context.
   */
  app.get('/auth/error', (req: Request, res: Response) => {
    const { heading, message } = getMessage(req.query.error, 'auth-error');
    res.render('auth/error', { heading, message });
  });

  /**
   * ZITADEL UserInfo endpoint
   *
   * Fetches extended user information from ZITADEL's UserInfo endpoint using the
   * current session's access token. Provides real-time user data including roles,
   * custom attributes, and organization membership that may not be in the cached session.
   *
   * @param req - Express Request object
   * @param res - Express Response object
   */
  app.get(
    '/auth/userinfo',
    requireAuth,
    async (req: Request, res: Response) => {
      const session = await getSession(req, authConfig);

      if (!session) {
        res.status(401).json({ error: 'Unauthorized' });
      } else if (!session.accessToken) {
        res.status(401).json({ error: 'No access token available' });
      } else {
        try {
          const idpRes = await fetch(
            `${config.ZITADEL_DOMAIN}/oidc/v1/userinfo`,
            {
              headers: {
                Authorization: `Bearer ${session.accessToken}`,
              },
            },
          );

          if (!idpRes.ok) {
            res
              .status(idpRes.status)
              .json({ error: `UserInfo API error: ${idpRes.status}` });
          } else {
            const userInfo = await idpRes.json();
            res.json(userInfo);
          }
        } catch (err) {
          console.error('UserInfo fetch failed:', err);
          res.status(500).json({ error: 'Failed to fetch user info' });
        }
      }
    },
  );

  /**
   * Home page.
   *
   * Retrieves the current Auth.js session (if any) to determine whether the
   * user is signed in, then renders the 'index' template. The template is
   * provided with:
   * - `isAuthenticated`: a boolean flag indicating session presence
   * - `loginUrl`: the URL to begin the sign-in flow
   *
   * @param req  Express Request object for the incoming HTTP request
   * @param res  Express Response object used to render the 'index' view
   */
  app.get('/', async (req: Request, res: Response) => {
    const session = await getSession(req, authConfig);
    res.render('index', {
      isAuthenticated: !!session,
      loginUrl: '/auth/signin/zitadel',
    });
  });

  /**
   * GET /auth/logout/success
   *
   * Renders a confirmation page indicating the user has successfully logged out.
   * After displaying a success message, the template may include client-side logic
   * to redirect the user back to the home page after a short delay.
   *
   * @param req  - Express Request object (unused)
   * @param res  - Express Response object used to render the success view
   */
  app.get('/auth/logout/success', (_req: Request, res: Response) => {
    res.render('auth/logout/success');
  });

  /**
   * GET /auth/logout/error
   *
   * Displays a user-friendly error page for failed logout attempts. This page is
   * typically shown when a security check fails during the logout process,
   * commonly due to a CSRF protection failure where the `state` parameter from
   * the identity provider does not match the one stored securely in session.
   *
   * @param req   - Express Request object containing the query parameter `reason`
   * @param res   - Express Response object used to render the error view
   */
  app.get('/auth/logout/error', (req: Request, res: Response) => {
    res.render('auth/logout/error', {
      reason: req.query.reason || 'An unknown error occurred.',
    });
  });

  /**
   * Mounts Auth.js Express middleware to handle OAuth 2.0/OIDC authentication flows.
   *
   * This middleware provides the complete authentication infrastructure including
   * sign-in, sign-out, callback handling, session management, and CSRF protection.
   * It automatically creates endpoints for OAuth flows under the `/auth` path.
   *
   * The ExpressAuth middleware registers several endpoints for authentication:
   * - `/auth/signin/[provider]` - Initiates OAuth flow with specified provider
   * - `/auth/callback/[provider]` - Handles OAuth callback from provider
   * - `/auth/signout` - Signs out user and clears session
   * - `/auth/session` - Returns current session data as JSON
   * - `/auth/csrf` - Returns CSRF token for form submissions
   *
   * IMPORTANT: All custom `/auth/*` routes MUST be defined BEFORE this
   * middleware to prevent conflicts. Express matches routes in definition order,
   * and this middleware will intercept ALL `/auth/*` requests that don't match
   * your custom routes first.
   *
   * Correct Order:
   * ```typescript
   * // ✓ Define custom auth routes FIRST
   * app.get('/auth/logout/success', handler);
   * app.get('/auth/logout/error', handler);
   * app.get('/auth/error', handler);
   *
   * // ✓ Mount ExpressAuth AFTER custom routes
   * app.use('/auth', ExpressAuth(authConfig));
   * ```
   *
   * Incorrect Order (will cause UnknownAction errors):
   * ```typescript
   * // ✗ ExpressAuth intercepts everything first
   * app.use('/auth', ExpressAuth(authConfig));
   *
   * // ✗ These routes will never be reached
   * app.get('/auth/logout/success', handler);
   * ```
   *
   * If a request matches `/auth/*` but isn't a recognized Auth.js action, the
   * middleware throws an UnknownAction error. This happens when:
   * - Custom auth routes are defined after this middleware
   * - Invalid or misspelled auth endpoints are accessed
   * - Routes conflict with Auth.js internal naming conventions
   *
   * The middleware behavior is controlled by the `authConfig` object which
   * includes providers, session settings, callbacks, and security options.
   * See `authConfig` in `auth/index.ts` for complete configuration details.
   *
   * @see {@link https://authjs.dev/reference/express} Auth.js Express documentation
   * @see {@link authConfig} Complete authentication configuration
   */
  app.use('/auth', ExpressAuth(authConfig));

  /**
   * GET /profile
   *
   * Profile page with detailed user information.
   *
   * Renders a comprehensive view of the signed-in user’s profile — for example,
   * display name, email, roles, and any custom attributes — as well as session
   * metadata (tokens, expiry, etc.). This route is guarded by `requireAuth`, so
   * unauthenticated requests are automatically redirected into the sign-in flow.
   * After confirming authentication, we call `getSession` to retrieve the latest
   * session data, then render the `profile` template with the full `user` object.
   *
   * @param req  - Express Request object, guaranteed to have an authenticated session
   * @param res  - Express Response object, used to render the profile view
   */
  app.get('/profile', requireAuth, async (req: Request, res: Response) => {
    const session = await getSession(req, authConfig);
    res.render('profile', { userJson: JSON.stringify(session, null, 2) });
  });

  /**
   * Catch-all 404 handler.
   *
   * This middleware is invoked when no other route matches the incoming request.
   * It responds with a 404 status and renders the 'not-found' template, providing
   * a user-friendly page indicating that the requested resource could not be found.
   *
   * @param req  - Express Request object for the incoming request
   * @param res  - Express Response object used to send the 404 view
   * @returns    void
   */
  app.use((_req: Request, res: Response) => {
    res.status(404).render('not-found', {
      //
    });
  });

  return app;
}
