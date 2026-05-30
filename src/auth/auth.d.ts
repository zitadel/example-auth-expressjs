import type { Session as CoreSession } from '@auth/core/types';
import type { JWT as CoreJWT } from '@auth/core/jwt';

/**
 * Extend Auth.js core Session to include ZITADEL tokens.
 * This augmentation must be in your tsconfig's include/typeRoots.
 */
declare module '@auth/core/types' {
  // noinspection JSUnusedGlobalSymbols
  interface Session extends CoreSession {
    /** OpenID Connect ID token */
    idToken?: string;
    /** OAuth2 access token */
    accessToken?: string;
    /** Error flag when refresh fails */
    error?: string;
  }
}

/**
 * Extend Auth.js core JWT to store ZITADEL token metadata.
 */
declare module '@auth/core/jwt' {
  // noinspection JSUnusedGlobalSymbols
  interface JWT extends CoreJWT {
    /** OpenID Connect ID token */
    idToken?: string;
    /** OAuth2 access token */
    accessToken?: string;
    /** OAuth2 refresh token */
    refreshToken?: string;
    /** Timestamp in ms when access token expires */
    expiresAt?: number;
    /** Error flag when refresh fails */
    error?: string;
  }
}
