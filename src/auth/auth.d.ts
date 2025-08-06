import '@auth/express';

/**
 * Extends NextAuth.js Session interface to include ZITADEL-specific tokens.
 *
 * This makes ZITADEL tokens available throughout your application via the
 * useSession() hook and getServerSession() function.
 */
declare module '@auth/express' {
  // noinspection JSUnusedGlobalSymbols
  interface Session {
    /** The OpenID Connect ID token from ZITADEL - used for logout and user identification */
    idToken?: string;
    /** The OAuth 2.0 access token - used for making authenticated API calls to ZITADEL */
    accessToken?: string;
    /** Error state indicating if token refresh failed - user needs to re-authenticate */
    error?: string;
  }
}

/**
 * Extends NextAuth.js JWT interface to store all necessary tokens and metadata.
 *
 * This internal interface stores tokens securely in the encrypted JWT that
 * NextAuth uses for session management.
 */
declare module '@auth/core/jwt' {
  // noinspection JSUnusedGlobalSymbols
  interface JWT {
    /** The OpenID Connect ID token from ZITADEL */
    idToken?: string;
    /** The OAuth 2.0 access token for making API calls */
    accessToken?: string;
    /** The OAuth 2.0 refresh token for getting new access tokens */
    refreshToken?: string;
    /** Unix timestamp (in milliseconds) when the access token expires */
    expiresAt?: number;
    /** Error flag set when token refresh fails */
    error?: string;
  }
}
