// noinspection JSUnusedGlobalSymbols

/**
 * Represents a user from Zitadel identity provider with core profile information.
 * This interface remains the same.
 */
export interface ZitadelUser {
  id: string;
  email: string;
  name: string;
  preferred_username: string;
}
/**
 * Global Express namespace extension.
 */
declare global {
  // eslint-disable-next-line
  namespace Express {
    // eslint-disable-next-line
    interface User extends ZitadelUser {
      //
    }
  }
}
