import { Platform } from 'react-native';
import jwt from 'jwt-lite';
import { WebBrowser, SecureStore } from 'expo';
import * as util from './util';
import * as clientUtil from './token-client-util';
import * as oidc from './oidc';

export default class TokenClient {
  constructor(config = {}) {
    const missing = [];
    if (!config.issuer) missing.push('issuer');
    if (!config.redirect_uri) missing.push('redirect_uri');
    if (!config.client_id) missing.push('client_id');
    if (missing.length) throw new Error(`Must provide ${missing}`);

    this.issuer = config.issuer;
    this.authorization_endpoint = config.authorization_endpoint;
    delete config.issuer;
    delete config.authorization_endpoint;

    this._authContext = null;
    this._storageKey = config.storageKey || 'authContext';
    this._keychainService = config.keychainService;
    this._keychainAccessible = SecureStore[config.keychainAccessible || 'WHEN_UNLOCKED_THIS_DEVICE_ONLY'];
    delete config.storageKey;
    delete config.keychainService;
    delete config.keychainAccessible;

    this.config = config;
  }

  async signInWithRedirect(options = {}) {
    return oidc.performPkceCodeFlow(this, options, async function redirect(authorizeUri, redirectUri) {
      const result = await WebBrowser.openAuthSessionAsync(authorizeUri, redirectUri);

      if (result.type === 'cancel') {
        throw new Error('User cancelled the auth flow');
      }

      if (result.type !== 'success') {
        throw new Error(`Could not complete auth flow: ${result.url}`);
      }

      return util.urlFormDecode(result.url.split('?')[1]);
    });
  }

  async getIdToken() {
    const authContext = await clientUtil.getAuthContext(this);
    if (!authContext || !authContext.idToken) return;
    if (authContext.idToken.expiresAt < Math.floor(Date.now()/1000)) {
      delete authContext.idToken;
      await clientUtil.setAuthContext(this, authContext);
      return;
    }
    return authContext.idToken.string;
  }

  async getAccessToken() {
    const authContext = await clientUtil.getAuthContext(this);
    if (!authContext || !authContext.accessToken) return;
    if (authContext.accessToken.expiresAt < Math.floor(Date.now()/1000)) {
      delete authContext.accessToken;
      return oidc.refreshAccessToken(this);
    }
    return authContext.accessToken.string;
  }

  async getUser() {
    const accessToken = await this.getAccessToken();
    if (accessToken) {
      const wellKnown = await clientUtil.getWellKnown(this);
      try {
        return await clientUtil.request(`${wellKnown.userinfo_endpoint}`, {
          headers: {
            'Authorization': `Bearer ${accessToken}`
          }
        });
      } catch(e) {
        if (e.name === 'ApiError' && !e.errorCode) {
          const authContext = await clientUtil.getAuthContext(this);
          delete authContext.accessToken;
          await clientUtil.setAuthContext(this, authContext);
          return;
        }
        throw e;
      }
    }
    const idToken = await this.getIdToken();
    if (idToken) {
      return jwt.decode(idToken).claimsSet;
    }
  }

  async signOut() {
    delete this._authContext;
    await SecureStore.deleteItemAsync(this._storageKey);
  }
}