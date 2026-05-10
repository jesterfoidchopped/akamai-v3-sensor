/**
 * HTTPCloak Node.js Client - ESM Module
 *
 * A fetch/axios-compatible HTTP client with browser fingerprint emulation.
 * Provides TLS fingerprinting for HTTP requests.
 */

import { createRequire } from "module";
const require = createRequire(import.meta.url);

const cjs = require("./index.js");

export const Session = cjs.Session;
export const LocalProxy = cjs.LocalProxy;
export const Response = cjs.Response;
export const FastResponse = cjs.FastResponse;
export const StreamResponse = cjs.StreamResponse;
export const Cookie = cjs.Cookie;
export const RedirectInfo = cjs.RedirectInfo;
export const HTTPCloakError = cjs.HTTPCloakError;
export const SessionCacheBackend = cjs.SessionCacheBackend;

export const Preset = cjs.Preset;

export const configure = cjs.configure;
export const configureSessionCache = cjs.configureSessionCache;
export const clearSessionCache = cjs.clearSessionCache;

export const get = cjs.get;
export const post = cjs.post;
export const put = cjs.put;
export const patch = cjs.patch;
export const head = cjs.head;
export const options = cjs.options;
export const request = cjs.request;

export const version = cjs.version;
export const availablePresets = cjs.availablePresets;

export const setEchDnsServers = cjs.setEchDnsServers;
export const getEchDnsServers = cjs.getEchDnsServers;

const del = cjs.delete;
export { del as delete };

export default cjs;
