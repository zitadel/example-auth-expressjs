// file: src/app.ts
import express, { Application, Response } from 'express';
import cookieParser from 'cookie-parser';

import {
  AuthReq,
  createZitadelMiddleware,
} from '../../express-zitadel/src/zitadel.js';

/**
 * Creates, configures, and returns an Express application instance.
 * This function is now exported so it can be used by your entry-point file (index.ts).
 */
export async function createApp(): Promise<Application> {
  const app: Application = express();

  app.use(cookieParser());

  const { authRouter, requireAuthToken } = await createZitadelMiddleware();

  app.use(authRouter);

  /**
   * Landing page.
   */
  app.get('/', (_req: AuthReq, res: Response): void => {
    res.json({
      message:
        'This is a public page. Try accessing the protected /profile route.',
      loginUrl: '/auth/login',
      profileUrl: '/profile',
    });
  });

  /**
   * GET /profile — protected by our new express-jwt based middleware.
   * Note that the route handler itself DOES NOT CHANGE because our middleware
   * wrapper conveniently populates `req.user` for us.
   */
  app.get(
    '/profile',
    requireAuthToken, // This is now an array of middleware handlers
    (req: AuthReq, res: Response): void => {
      // If we get here, the token is valid and req.user is populated.
      res.json({
        message: 'This is a protected route. Your token is valid.',
        user: req.user,
      });
    },
  );

  return app;
}
