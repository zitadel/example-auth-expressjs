import express, { Application, Response } from 'express';

import {
  AuthReq,
  createZitadelMiddleware,
  ensureAuth,
  ZitadelConfig,
} from './zitadel.js';

const app: Application = express();
app.use(await createZitadelMiddleware({} as ZitadelConfig));

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
 * GET /profile — protected endpoint that simply echos the `ZitadelUser`
 * stored in the current session.
 */
app.get('/profile', ensureAuth, (req: AuthReq, res: Response): void => {
  res.json({ user: req.user });
});

export default app;
