import type { AuthenticateCallback } from 'passport';
import {
  Strategy as OpenIDConnectStrategy,
  StrategyOptions as OIDCStrategyOptions,
  VerifyFunction,
} from 'openid-client/passport';
import * as oidc from 'openid-client';
import { randomUUID } from 'node:crypto';

/**
 * Defines the shape of the user object that ZITADEL returns. It includes
 * the standard OIDC user info and adds the `id` and `id_token` for
 * session management and logout purposes.
 */
export interface ZitadelUser extends oidc.UserInfoResponse {
  id: string;
  id_token?: string;
}

/**
 * Configuration options required to discover and initialize the
 * `ZitadelStrategy`.
 */
export interface ZitadelStrategyOptions {
  domain: string;
  clientId: string;
  clientSecret?: string;
  callbackURL: string;
  scope: string;
  /**
   * The default URI to redirect to after the logout is complete.
   */
  postLogoutRedirectUrl: string;
}

/**
 * Options for building an OpenID Connect RP‑Initiated Logout URL.
 *
 * Only `id_token_hint`, `post_logout_redirect_uri`, and `state` are typically required.
 * Other fields are optional and only needed for specific OP behaviors.
 */
export interface LogoutUrlOptions {
  /**
   * The ID Token previously issued to the user. Used by the OP to identify and
   * terminate the correct session. Strongly recommended when available.
   *
   * Sent as the `id_token_hint` query parameter.
   */
  id_token_hint?: string;

  /**
   * OAuth 2.0 Client Identifier registered at the OP.
   *
   * OPTIONAL. When both `client_id` and `id_token_hint` are present, the OP MUST
   * verify that this client_id matches the one that was used to issue the ID Token.
   *
   * Common use cases:
   *  - You supply `post_logout_redirect_uri` but have no `id_token_hint`.
   *  - Your `id_token_hint` is a symmetrically encrypted ID Token and the OP
   *    needs the client_id to decrypt it.
   *
   * Sent as the `client_id` query parameter.
   */
  client_id?: string;

  /**
   * Where the OP should redirect the user after logout. Must be pre‑registered.
   *
   * Sent as `post_logout_redirect_uri`.
   * If you always use a single value from config, you can omit this here.
   */
  post_logout_redirect_uri?: string;

  /**
   * Opaque value you generate to protect against CSRF and to correlate the
   * logout response. Store it and verify it when the user returns.
   *
   * Sent as `state`.
   */
  state?: string;

  /**
   * Hint about the user being logged out (e.g., their subject identifier or
   * login name). Useful when you don’t have an ID Token.
   *
   * Sent as `logout_hint`.
   */
  logout_hint?: string;

  /**
   * Space‑separated list of BCP47 language tags to control the OP logout UI
   * language (e.g., "en fi").
   *
   * Sent as `ui_locales`.
   */
  ui_locales?: string;
}

// Internal strategy options, extending the base OIDC options.
interface InternalStrategyOptions extends OIDCStrategyOptions {
  postLogoutRedirectUrl: string;
}

type OIDCTokenSet = oidc.TokenEndpointResponse &
  oidc.TokenEndpointResponseHelpers;

/**
 * A reusable Passport strategy for authenticating with ZITADEL using
 * OpenID Connect.
 */
export class ZitadelStrategy extends OpenIDConnectStrategy {
  public readonly config: oidc.Configuration;
  public readonly postLogoutRedirectUrl: string;

  constructor(options: InternalStrategyOptions, verify: VerifyFunction) {
    super(options, verify);
    this.config = options.config;
    this.postLogoutRedirectUrl = options.postLogoutRedirectUrl;
  }

  public static async discover(
    options: ZitadelStrategyOptions,
  ): Promise<ZitadelStrategy> {
    const oidcConfig = await oidc.discovery(
      new URL(options.domain),
      options.clientId,
      options.clientSecret,
    );

    const strategyOptions: InternalStrategyOptions = {
      config: oidcConfig,
      name: 'zitadel',
      scope: options.scope,
      callbackURL: options.callbackURL,
      postLogoutRedirectUrl: options.postLogoutRedirectUrl,
    };

    return new ZitadelStrategy(strategyOptions, ZitadelStrategy.verify);
  }

  /**
   * Builds the RP-Initiated Logout URL.
   *
   * @param options - Options containing the optional id_token_hint.
   * @returns The full logout URL as a string.
   */
  public getLogoutUrl(options: LogoutUrlOptions = {}): string {
    return oidc
      .buildEndSessionUrl(this.config, {
        post_logout_redirect_uri: this.postLogoutRedirectUrl,
        ...(options.id_token_hint && { id_token_hint: options.id_token_hint }),
        ...(options.client_id && { client_id: options.client_id }),
        ...(options.logout_hint && { logout_hint: options.logout_hint }),
        ...(options.ui_locales && { ui_locales: options.ui_locales }),
        state: randomUUID(),
      })
      .toString();
  }

  private static verify(
    tokenSet: OIDCTokenSet,
    done: AuthenticateCallback,
  ): void {
    const claims = tokenSet.claims();
    if (!claims) {
      return done(new Error('Failed to get claims from token set.'));
    }

    const user: ZitadelUser = {
      ...claims,
      id: claims.sub,
      id_token: tokenSet.id_token,
    };

    return done(null, user);
  }
}
