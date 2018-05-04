/*
 * Copyright (c) 2017, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

import { Inject, Injectable, NgZone } from "@angular/core";
import { Router, NavigationExtras } from "@angular/router";

import { OKTA_CONFIG, OktaConfig } from "../models/okta.config";
import { UserClaims } from "../models/user-claims";

import packageInfo from "../packageInfo";

/**
 * Import the okta-auth-js library
 */
import * as OktaAuth from "@okta/okta-auth-js";
import { Observable } from "rxjs/Observable";
import { Observer } from "rxjs/Observer";

@Injectable()
export class OktaAuthService {
  private _oktaAuth: OktaAuth;
  private config: OktaConfig;
  private observers: Observer<boolean>[];
  $authenticationState: Observable<boolean>;

  oktaAuth(callback: (oktaAuth: OktaAuth) => void): void {
    this.ngZone.runOutsideAngular(() => callback(this._oktaAuth));
  }

  constructor(
    @Inject(OKTA_CONFIG) private auth: OktaConfig,
    private router: Router,
    private ngZone: NgZone
  ) {
    const missing: string[] = [];

    if (!auth.issuer) {
      missing.push("issuer");
    }
    if (!auth.clientId) {
      missing.push("clientId");
    }
    if (!auth.redirectUri) {
      missing.push("redirectUri");
    }

    if (missing.length) {
      throw new Error(`${missing.join(", ")} must be defined`);
    }

    this.observers = [];

    this.ngZone.runOutsideAngular(() => {
      this._oktaAuth = new OktaAuth({
        url: auth.issuer.split("/oauth2/")[0],
        clientId: auth.clientId,
        issuer: auth.issuer,
        redirectUri: auth.redirectUri
      });

      this._oktaAuth.userAgent = `${packageInfo.name}/${packageInfo.version} ${
        this._oktaAuth.userAgent
      }`;
    });

    /**
     * Scrub scopes to ensure 'openid' is included
     */
    auth.scope = this.scrubScopes(auth.scope);

    /**
     * Cache the auth config.
     */
    this.config = auth;

    this.$authenticationState = new Observable(
      (observer: Observer<boolean>) => {
        this.observers.push(observer);
      }
    );
  }

  /**
   * Checks if there is an access token and id token
   */
  async isAuthenticated(): Promise<boolean> {
    const accessToken = await this.getAccessToken();
    const idToken = await this.getIdToken();
    return !!(accessToken || idToken);
  }

  private async emitAuthenticationState(state: boolean) {
    this.observers.forEach(observer => observer.next(state));
  }

  /**
   * Returns the current accessToken in the tokenManager.
   */
  async getAccessToken(): Promise<string | undefined> {
    let accessToken;
    this.oktaAuth(oktaAuth => {
      accessToken = oktaAuth.tokenManager.get("accessToken");
    });
    return accessToken ? accessToken.accessToken : undefined;
  }

  /**
   * Returns the current idToken in the tokenManager.
   */
  async getIdToken(): Promise<string | undefined> {
    let idToken;
    this.oktaAuth(oktaAuth => {
      idToken = oktaAuth.tokenManager.get("idToken");
    });

    return idToken ? idToken.idToken : undefined;
  }

  /**
   * Returns user claims from the /userinfo endpoint if an
   * accessToken is provided or parses the available idToken.
   */
  async getUser(): Promise<UserClaims | undefined> {
    let accessToken;
    let idToken;
    this.oktaAuth(oktaAuth => {
      accessToken = oktaAuth.tokenManager.get("accessToken");
      idToken = oktaAuth.tokenManager.get("idToken");
    });

    if (accessToken && idToken) {
      let userinfo;
      this.oktaAuth(async oktaAuth => {
        userinfo = await oktaAuth.token.getUserInfo(accessToken);
      });

      if (userinfo.sub === idToken.claims.sub) {
        // Only return the userinfo response if subjects match to
        // mitigate token substitution attacks
        return userinfo;
      }
    }
    return idToken ? idToken.claims : undefined;
  }

  /**
   * Returns the configuration object used.
   */
  getOktaConfig(): OktaConfig {
    return this.config;
  }

  /**
   * Launches the login redirect.
   * @param fromUri
   * @param additionalParams
   */
  loginRedirect(fromUri?: string, additionalParams?: object) {
    if (fromUri) {
      this.setFromUri(fromUri);
    }

    this.oktaAuth(async oktaAuth => {
      oktaAuth.token.getWithRedirect({
        responseType: (this.config.responseType || "id_token token").split(" "),
        // Convert scopes to list of strings
        scopes: this.config.scope.split(" "),
        ...additionalParams
      });
    });
  }

  /**
   * Stores the intended path to redirect after successful login.
   * @param uri
   * @param queryParams
   */
  setFromUri(uri: string, queryParams?: object) {
    const json = JSON.stringify({
      uri: uri,
      params: queryParams
    });
    localStorage.setItem("referrerPath", json);
  }

  /**
   * Returns the referrer path from localStorage or app root.
   */
  getFromUri(): { uri: string; extras: NavigationExtras } {
    const referrerPath = localStorage.getItem("referrerPath");
    localStorage.removeItem("referrerPath");

    const path = JSON.parse(referrerPath) || { uri: "/", params: {} };
    const navigationExtras: NavigationExtras = {
      queryParams: path.params
    };

    return {
      uri: path.uri,
      extras: navigationExtras
    };
  }

  /**
   * Parses the tokens from the callback URL.
   */
  async handleAuthentication(): Promise<void> {
    let tokens;
    this.oktaAuth(async oktaAuth => {
      tokens = await oktaAuth.token.parseFromUrl();
      tokens.forEach(token => {
        if (token.idToken) {
          oktaAuth.tokenManager.add("idToken", token);
        }
        if (token.accessToken) {
          oktaAuth.tokenManager.add("accessToken", token);
        }
      });
    });

    if (await this.isAuthenticated()) {
      this.emitAuthenticationState(true);
    }
    /**
     * Navigate back to the initial view or root of application.
     */
    const fromUri = this.getFromUri();
    this.router.navigate([fromUri.uri], fromUri.extras);
  }

  /**
   * Clears the user session in Okta and removes
   * tokens stored in the tokenManager.
   * @param uri
   */
  async logout(uri?: string): Promise<void> {
    this.oktaAuth(async oktaAuth => {
      oktaAuth.tokenManager.clear();
      await oktaAuth.signOut();
    });

    this.emitAuthenticationState(false);
    this.router.navigate([uri || "/"]);
  }

  /**
   * Scrub scopes to ensure 'openid' is included
   * @param scopes
   */
  scrubScopes(scopes: string): string {
    if (!scopes) {
      return "openid email";
    }
    if (scopes.indexOf("openid") === -1) {
      return scopes + " openid";
    }
    return scopes;
  }
}
