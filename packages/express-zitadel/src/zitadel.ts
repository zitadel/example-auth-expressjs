import {
  NextFunction,
  Request,
  Response,
  Router,
  RequestHandler,
} from 'express';
import * as oidc from 'openid-client';
import { ZitadelUser } from './types.js';
import { randomUUID } from 'node:crypto';
import jwt from 'jsonwebtoken';
import { expressjwt, Request as JWTRequest } from 'express-jwt';
import { expressJwtSecret, GetVerificationKey } from 'jwks-rsa';

export type AuthReq = Request & { user?: ZitadelUser };

interface StateTokenPayload {
  jti: string;
  pkceCodeVerifier: string;
}

export interface ZitadelConfig {
  domain: string;
  clientId: string;
  clientSecret: string;
  callbackURL: string;
  nodeEnv?: string;
  postLogoutURL?: string;
  postLoginURL?: string;
  stateSecret: string;
}

/**
 * Creates and configures the Zitadel authentication middleware.
 * This is now 100% stateless, using a signed JWT for the state parameter.
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
    nodeEnv: config?.nodeEnv || process.env.NODE_ENV,
    stateSecret: config?.stateSecret || process.env.SESSION_SECRET!,
  };

  const oidcClient = await oidc.discovery(
    new URL(zitadelConfig.domain),
    zitadelConfig.clientId,
    zitadelConfig.clientSecret,
  );

  const authRouter = Router();

  /**
   * GET /auth/login - Manually builds the OIDC authorization request.
   */
  const handleLogin: RequestHandler = async (req, res, next) => {
    try {
      const pkceCodeVerifier = oidc.randomPKCECodeVerifier();
      const code_challenge =
        await oidc.calculatePKCECodeChallenge(pkceCodeVerifier);
      const code_challenge_method = 'S256';

      const statePayload: StateTokenPayload = {
        jti: randomUUID(),
        pkceCodeVerifier: pkceCodeVerifier,
      };

      const state = jwt.sign(statePayload, zitadelConfig.stateSecret, {
        expiresIn: '10m',
      });

      const authorizationUrl = oidc.buildAuthorizationUrl(oidcClient, {
        scope: 'openid profile email',
        state: state,
        code_challenge,
        code_challenge_method,
        redirect_uri: zitadelConfig.callbackURL,
      });

      res.redirect(authorizationUrl.toString());
    } catch (error) {
      next(error);
    }
  };

  authRouter.get('/auth/login', handleLogin);

  /**
   * GET /auth/callback - Manually handles the OIDC callback.
   */
  const handleCallback: RequestHandler = async (
    req,
    res,
    next,
  ): Promise<void> => {
    try {
      const stateFromQuery = req.query.state as string;

      if (!stateFromQuery) {
        res.status(400).send('State parameter is missing');
        return;
      }

      let decodedState: StateTokenPayload;
      try {
        decodedState = jwt.verify(
          stateFromQuery,
          zitadelConfig.stateSecret,
        ) as StateTokenPayload;
      } catch (err) {
        res.status(403).send('Invalid or expired state token');
        return;
      }

      const callbackUrl = new URL(
        req.originalUrl,
        `${req.protocol}://${req.get('host')}`,
      );

      const tokenSet = await oidc.authorizationCodeGrant(
        oidcClient,
        callbackUrl,
        {
          pkceCodeVerifier: decodedState.pkceCodeVerifier,
          expectedState: stateFromQuery,
        },
      );

      const idToken = tokenSet.id_token;
      if (!idToken) {
        res.status(500).json({ error: 'Failed to get ID token' });
        return;
      }

      const maxAge = (tokenSet.expires_in ?? 3600) * 1000;
      res.cookie('id_token', idToken, {
        httpOnly: true,
        secure: zitadelConfig.nodeEnv === 'production',
        maxAge: maxAge,
        sameSite: 'lax',
      });

      res.redirect(zitadelConfig.postLoginURL || '/profile');
    } catch (error) {
      next(error);
    }
  };

  authRouter.get('/auth/callback', handleCallback);

  /**
   * GET /auth/logout - Clears local and server session artifacts.
   */
  const handleLogout: RequestHandler = (req, res) => {
    res.clearCookie('id_token');

    res.setHeader('Clear-Site-Data', '"*"');
    res.redirect(
      oidc
        .buildEndSessionUrl(oidcClient, {
          post_logout_redirect_uri:
            zitadelConfig.postLogoutURL ||
            `${req.protocol}://${req.get('host')}`,
          state: randomUUID(),
        })
        .toString(),
    );
  };

  authRouter.get('/auth/logout', handleLogout);

  const requireAuthToken = [
    expressjwt({
      secret: expressJwtSecret({
        cache: true,
        rateLimit: true,
        jwksRequestsPerMinute: 5,
        jwksUri: oidcClient.serverMetadata().jwks_uri!,
      }) as GetVerificationKey,
      audience: zitadelConfig.clientId,
      issuer: oidcClient.serverMetadata().issuer,
      algorithms: ['RS256'],
      getToken: (req: Request) => req.cookies.id_token,
    }),
    (req: JWTRequest, _res: Response, next: NextFunction) => {
      if (req.auth) {
        req.user = {
          id: req.auth.sub!,
          email: (req.auth.email as string) ?? '',
          name: (req.auth.name as string) ?? '',
          preferred_username: (req.auth.preferred_username as string) ?? '',
        };
      }
      next();
    },
    (err: any, _req: Request, res: Response, next: NextFunction) => {
      if (err.name === 'UnauthorizedError') {
        res.status(401).json({ error: 'Unauthorized: Invalid token.' });
      } else {
        next(err);
      }
    },
  ];

  return { authRouter, requireAuthToken };
}
