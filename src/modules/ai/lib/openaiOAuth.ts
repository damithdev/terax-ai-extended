import { invoke } from "@tauri-apps/api/core";
import { KEYRING_SERVICE } from "../config";
import {
  joinParts,
  oauthErrorMessage,
  oauthPartAccounts,
  partAccount,
  postForm,
  readJson,
  secretDelete,
  secretGet,
  secretSet,
  sleep,
  splitForCredential,
  throwIfAborted,
  WIN_CREDENTIAL_MAX_CHARS,
} from "./oauthKeychain";
import { proxyFetch } from "./proxyFetch";

export { WIN_CREDENTIAL_MAX_CHARS };

export const OPENAI_OAUTH_ACCOUNT = "openai-oauth";
export const OPENAI_OAUTH_ACCESS_PREFIX = "openai-oauth-access";
export const OPENAI_OAUTH_REFRESH_PREFIX = "openai-oauth-refresh";
const MAX_STORED_PARTS = 16;

/** Codex CLI public client. Do not invent a new id. */
export const OPENAI_OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
export const OPENAI_OAUTH_REFRESH_SKEW_MS = 2 * 60 * 1000;
export const OPENAI_CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex";
export const OPENAI_CODEX_ORIGINATOR = "codex_cli_rs";
export const OPENAI_DEVICE_VERIFICATION_URL =
  "https://auth.openai.com/codex/device";

const USERCODE_URL = "https://auth.openai.com/api/accounts/deviceauth/usercode";
const DEVICE_TOKEN_URL =
  "https://auth.openai.com/api/accounts/deviceauth/token";
const TOKEN_URL = "https://auth.openai.com/oauth/token";
const DEVICE_REDIRECT_URI = "https://auth.openai.com/deviceauth/callback";
const USERINFO_URL = "https://auth.openai.com/api/accounts/oauth/userinfo";
const DEVICE_FLOW_TTL_MS = 15 * 60 * 1000;
const DEFAULT_POLL_INTERVAL_MS = 5000;
const DEFAULT_TOKEN_EXPIRES_SEC = 3600;
const CHATGPT_AUTH_NS = "https://api.openai.com/auth";

export type OpenAIOauthSession = {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
  accountId?: string;
  email?: string;
  name?: string;
};

export type OpenAIDeviceCode = {
  deviceAuthId: string;
  userCode: string;
  verificationUrl: string;
  expiresAt: number;
  intervalMs: number;
};

let refreshInFlight: Promise<string | null> | null = null;

export function isOpenAIApiKey(value: string | null | undefined): boolean {
  return typeof value === "string" && value.startsWith("sk-");
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object"
    ? (value as Record<string, unknown>)
    : null;
}

function decodeBase64Url(segment: string): string {
  const pad = "=".repeat((4 - (segment.length % 4)) % 4);
  const b64 = (segment + pad).replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(b64);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

function jwtPayload(
  token: string | null | undefined,
): Record<string, unknown> | null {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length < 2) return null;
  try {
    const parsed: unknown = JSON.parse(decodeBase64Url(parts[1]));
    return asRecord(parsed);
  } catch {
    return null;
  }
}

/** Display-only: the JWT signature is not verified. */
export function extractAccountId(
  idToken?: string | null,
  accessToken?: string | null,
): string | undefined {
  for (const token of [idToken, accessToken]) {
    const payload = jwtPayload(token);
    if (!payload) continue;
    if (isNonEmptyString(payload.chatgpt_account_id)) {
      return payload.chatgpt_account_id;
    }
    const ns = asRecord(payload[CHATGPT_AUTH_NS]);
    if (ns && isNonEmptyString(ns.chatgpt_account_id)) {
      return ns.chatgpt_account_id;
    }
    const orgs = payload.organizations;
    if (Array.isArray(orgs) && orgs[0]) {
      const org = asRecord(orgs[0]);
      if (org && isNonEmptyString(org.id)) return org.id;
    }
  }
  return undefined;
}

export function emailFromIdToken(
  idToken: string | null | undefined,
): string | undefined {
  const payload = jwtPayload(idToken);
  return payload && isNonEmptyString(payload.email) ? payload.email : undefined;
}

export function parseOAuthSession(raw: unknown): OpenAIOauthSession | null {
  let value: unknown = raw;
  if (typeof value === "string") {
    try {
      value = JSON.parse(value);
    } catch {
      return null;
    }
  }
  const o = asRecord(value);
  if (!o) return null;
  if (!isNonEmptyString(o.accessToken) || !isNonEmptyString(o.refreshToken)) {
    return null;
  }
  if (typeof o.expiresAt !== "number" || !Number.isFinite(o.expiresAt)) {
    return null;
  }
  const session: OpenAIOauthSession = {
    accessToken: o.accessToken,
    refreshToken: o.refreshToken,
    expiresAt: o.expiresAt,
  };
  if (isNonEmptyString(o.accountId)) session.accountId = o.accountId;
  if (isNonEmptyString(o.email)) session.email = o.email;
  if (isNonEmptyString(o.name)) session.name = o.name;
  return session;
}

export function sessionNeedsRefresh(
  session: Pick<OpenAIOauthSession, "expiresAt">,
  now = Date.now(),
): boolean {
  return session.expiresAt - now <= OPENAI_OAUTH_REFRESH_SKEW_MS;
}

export function credentialsFromTokenResponse(
  body: unknown,
  previous?: Pick<
    OpenAIOauthSession,
    "refreshToken" | "email" | "name" | "accountId"
  >,
  now = Date.now(),
): OpenAIOauthSession | null {
  const o = asRecord(body);
  if (!o || !isNonEmptyString(o.access_token)) return null;
  const refresh = isNonEmptyString(o.refresh_token)
    ? o.refresh_token
    : (previous?.refreshToken ?? "");
  if (!refresh) return null;
  const expiresInRaw =
    typeof o.expires_in === "number" ? o.expires_in : Number(o.expires_in);
  const expiresIn =
    Number.isFinite(expiresInRaw) && expiresInRaw > 0
      ? expiresInRaw
      : DEFAULT_TOKEN_EXPIRES_SEC;
  const idToken = isNonEmptyString(o.id_token) ? o.id_token : undefined;
  const payload = jwtPayload(idToken);
  const session: OpenAIOauthSession = {
    accessToken: o.access_token,
    refreshToken: refresh,
    expiresAt: now + expiresIn * 1000,
  };
  const accountId =
    extractAccountId(idToken, o.access_token) ?? previous?.accountId;
  const email = emailFromIdToken(idToken) ?? previous?.email;
  const name =
    payload && isNonEmptyString(payload.name) ? payload.name : previous?.name;
  if (accountId) session.accountId = accountId;
  if (email) session.email = email;
  if (name) session.name = name;
  return session;
}

export function parseDeviceUserCode(body: unknown): {
  deviceAuthId: string;
  userCode: string;
  intervalMs: number;
} | null {
  const o = asRecord(body);
  if (!o) return null;
  const deviceAuthId = isNonEmptyString(o.device_auth_id)
    ? o.device_auth_id
    : undefined;
  const userCode = isNonEmptyString(o.user_code)
    ? o.user_code
    : isNonEmptyString(o.usercode)
      ? o.usercode
      : undefined;
  if (!deviceAuthId || !userCode) return null;
  const seconds =
    typeof o.interval === "number" ? o.interval : Number(o.interval);
  const intervalMs =
    Number.isFinite(seconds) && seconds > 0
      ? Math.round(seconds * 1000)
      : DEFAULT_POLL_INTERVAL_MS;
  return { deviceAuthId, userCode, intervalMs };
}

export function parseDeviceGrant(body: unknown): {
  authorizationCode: string;
  codeVerifier: string;
} | null {
  const o = asRecord(body);
  if (!o) return null;
  if (
    !isNonEmptyString(o.authorization_code) ||
    !isNonEmptyString(o.code_verifier)
  ) {
    return null;
  }
  return {
    authorizationCode: o.authorization_code,
    codeVerifier: o.code_verifier,
  };
}

export type OAuthCredentialEntry = {
  account: string;
  password: string;
};

export function sessionToCredentialEntries(
  session: OpenAIOauthSession,
  maxChars = WIN_CREDENTIAL_MAX_CHARS,
): OAuthCredentialEntry[] {
  const access = splitForCredential(session.accessToken, maxChars);
  const refresh = splitForCredential(session.refreshToken, maxChars);
  const meta: Record<string, unknown> = {
    expiresAt: session.expiresAt,
    accessParts: access.length,
    refreshParts: refresh.length,
  };
  if (session.accountId) meta.accountId = session.accountId;
  if (session.email) meta.email = session.email;
  if (session.name) meta.name = session.name;
  return [
    { account: OPENAI_OAUTH_ACCOUNT, password: JSON.stringify(meta) },
    ...access.map((password, i) => ({
      account: partAccount(OPENAI_OAUTH_ACCESS_PREFIX, i),
      password,
    })),
    ...refresh.map((password, i) => ({
      account: partAccount(OPENAI_OAUTH_REFRESH_PREFIX, i),
      password,
    })),
  ];
}

export function sessionFromCredentialMap(
  map: Record<string, string | null | undefined>,
): OpenAIOauthSession | null {
  const raw = map[OPENAI_OAUTH_ACCOUNT];
  if (!raw) return null;
  const combined = parseOAuthSession(raw);
  if (combined) return combined;
  let meta: unknown;
  try {
    meta = JSON.parse(raw);
  } catch {
    return null;
  }
  const o = asRecord(meta);
  if (!o || typeof o.expiresAt !== "number" || !Number.isFinite(o.expiresAt)) {
    return null;
  }
  const access = joinParts(
    map,
    OPENAI_OAUTH_ACCESS_PREFIX,
    Number(o.accessParts),
  );
  const refresh = joinParts(
    map,
    OPENAI_OAUTH_REFRESH_PREFIX,
    Number(o.refreshParts),
  );
  if (!access || !refresh) return null;
  const session: OpenAIOauthSession = {
    accessToken: access,
    refreshToken: refresh,
    expiresAt: o.expiresAt,
  };
  if (isNonEmptyString(o.accountId)) session.accountId = o.accountId;
  if (isNonEmptyString(o.email)) session.email = o.email;
  if (isNonEmptyString(o.name)) session.name = o.name;
  return session;
}

async function postJson(
  url: string,
  payload: Record<string, string>,
  signal?: AbortSignal,
): Promise<Response> {
  return proxyFetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(payload),
    signal,
  });
}

export async function requestOpenAIDeviceCode(
  signal?: AbortSignal,
): Promise<OpenAIDeviceCode> {
  throwIfAborted(signal);
  const res = await postJson(
    USERCODE_URL,
    { client_id: OPENAI_OAUTH_CLIENT_ID },
    signal,
  );
  const body = await readJson(res);
  if (!res.ok) {
    throw new Error(
      oauthErrorMessage(
        body,
        "Failed to start ChatGPT sign-in. Enable device code authorization for Codex in ChatGPT Settings → Security.",
      ),
    );
  }
  const parsed = parseDeviceUserCode(body);
  if (!parsed) {
    throw new Error("ChatGPT did not return a device code.");
  }
  return {
    deviceAuthId: parsed.deviceAuthId,
    userCode: parsed.userCode,
    verificationUrl: OPENAI_DEVICE_VERIFICATION_URL,
    expiresAt: Date.now() + DEVICE_FLOW_TTL_MS,
    intervalMs: parsed.intervalMs,
  };
}

export async function pollOpenAIDeviceToken(
  device: OpenAIDeviceCode,
  signal?: AbortSignal,
): Promise<OpenAIOauthSession> {
  while (true) {
    throwIfAborted(signal);
    if (Date.now() >= device.expiresAt) {
      throw new Error("The sign-in code expired. Start again.");
    }
    const res = await postJson(
      DEVICE_TOKEN_URL,
      {
        device_auth_id: device.deviceAuthId,
        user_code: device.userCode,
      },
      signal,
    );
    if (res.status === 403 || res.status === 404) {
      const remaining = device.expiresAt - Date.now();
      if (remaining <= 0) {
        throw new Error("The sign-in code expired. Start again.");
      }
      await sleep(Math.min(device.intervalMs, remaining), signal);
      continue;
    }
    const body = await readJson(res);
    if (!res.ok) {
      throw new Error(oauthErrorMessage(body, "ChatGPT sign-in failed."));
    }
    const grant = parseDeviceGrant(body);
    if (!grant) {
      throw new Error("ChatGPT did not return an authorization code.");
    }
    const { status, body: tokenBody } = await postForm(
      TOKEN_URL,
      {
        grant_type: "authorization_code",
        client_id: OPENAI_OAUTH_CLIENT_ID,
        code: grant.authorizationCode,
        code_verifier: grant.codeVerifier,
        redirect_uri: DEVICE_REDIRECT_URI,
      },
      signal,
    );
    if (status < 200 || status >= 300) {
      throw new Error(
        oauthErrorMessage(tokenBody, "ChatGPT token exchange failed."),
      );
    }
    const session = credentialsFromTokenResponse(tokenBody);
    if (!session) {
      throw new Error("ChatGPT did not return an access token.");
    }
    return session;
  }
}

async function enrichIdentity(
  session: OpenAIOauthSession,
  signal?: AbortSignal,
): Promise<OpenAIOauthSession> {
  if (session.email && session.accountId) return session;
  try {
    throwIfAborted(signal);
    const res = await proxyFetch(USERINFO_URL, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${session.accessToken}`,
        Accept: "application/json",
      },
      signal,
    });
    if (!res.ok) return session;
    const o = asRecord(await readJson(res));
    if (!o) return session;
    const email = isNonEmptyString(o.email) ? o.email : session.email;
    const name = isNonEmptyString(o.name) ? o.name : session.name;
    const accountId = isNonEmptyString(o.chatgpt_account_id)
      ? o.chatgpt_account_id
      : session.accountId;
    return {
      ...session,
      ...(email ? { email } : {}),
      ...(name ? { name } : {}),
      ...(accountId ? { accountId } : {}),
    };
  } catch (e) {
    if (e instanceof DOMException && e.name === "AbortError") throw e;
    if (e instanceof Error && e.name === "AbortError") throw e;
    return session;
  }
}

export async function readOpenAIOauthSession(): Promise<OpenAIOauthSession | null> {
  const raw = await secretGet(OPENAI_OAUTH_ACCOUNT);
  if (!raw) return null;
  const combined = parseOAuthSession(raw);
  if (combined) return combined;
  let meta: unknown;
  try {
    meta = JSON.parse(raw);
  } catch {
    return null;
  }
  const o = asRecord(meta);
  if (!o) return null;
  const partAccounts = oauthPartAccounts(
    OPENAI_OAUTH_ACCESS_PREFIX,
    Number(o.accessParts),
    OPENAI_OAUTH_REFRESH_PREFIX,
    Number(o.refreshParts),
  );
  if (partAccounts.length === 0) return null;
  const map: Record<string, string | null> = { [OPENAI_OAUTH_ACCOUNT]: raw };
  try {
    const results = await invoke<(string | null)[]>("secrets_get_all", {
      service: KEYRING_SERVICE,
      accounts: partAccounts,
    });
    partAccounts.forEach((account, i) => {
      map[account] = results[i] ?? null;
    });
  } catch {
    for (const account of partAccounts) {
      map[account] = await secretGet(account);
    }
  }
  return sessionFromCredentialMap(map);
}

export async function writeOpenAIOauthSession(
  session: OpenAIOauthSession,
): Promise<void> {
  const entries = sessionToCredentialEntries(session);
  for (const entry of entries) {
    await secretSet(entry.account, entry.password);
  }
  const written = new Set(entries.map((e) => e.account));
  for (let i = 0; i < MAX_STORED_PARTS; i++) {
    const access = partAccount(OPENAI_OAUTH_ACCESS_PREFIX, i);
    const refresh = partAccount(OPENAI_OAUTH_REFRESH_PREFIX, i);
    if (!written.has(access)) await secretDelete(access);
    if (!written.has(refresh)) await secretDelete(refresh);
  }
}

export async function clearOpenAIOauthSession(): Promise<void> {
  await secretDelete(OPENAI_OAUTH_ACCOUNT);
  for (let i = 0; i < MAX_STORED_PARTS; i++) {
    await secretDelete(partAccount(OPENAI_OAUTH_ACCESS_PREFIX, i));
    await secretDelete(partAccount(OPENAI_OAUTH_REFRESH_PREFIX, i));
  }
}

export async function completeOpenAIOauthLogin(opts?: {
  signal?: AbortSignal;
  onDeviceCode?: (device: OpenAIDeviceCode) => void;
}): Promise<OpenAIOauthSession> {
  const device = await requestOpenAIDeviceCode(opts?.signal);
  opts?.onDeviceCode?.(device);
  const session = await pollOpenAIDeviceToken(device, opts?.signal);
  const withIdentity = await enrichIdentity(session, opts?.signal);
  await writeOpenAIOauthSession(withIdentity);
  return withIdentity;
}

async function refreshSession(
  session: OpenAIOauthSession,
): Promise<string | null> {
  try {
    const { status, body } = await postForm(TOKEN_URL, {
      grant_type: "refresh_token",
      refresh_token: session.refreshToken,
      client_id: OPENAI_OAUTH_CLIENT_ID,
    });
    if (status < 200 || status >= 300) {
      throw new Error(oauthErrorMessage(body, "ChatGPT token refresh failed."));
    }
    const next = credentialsFromTokenResponse(body, session);
    if (!next) throw new Error("ChatGPT token refresh failed.");
    await writeOpenAIOauthSession({
      ...session,
      ...next,
      email: next.email ?? session.email,
      name: next.name ?? session.name,
      accountId: next.accountId ?? session.accountId,
    });
    return next.accessToken;
  } catch {
    if (session.expiresAt > Date.now()) return session.accessToken;
    return null;
  }
}

export async function resolveOpenAIOauthSession(): Promise<OpenAIOauthSession | null> {
  const session = await readOpenAIOauthSession();
  if (!session) return null;
  if (!sessionNeedsRefresh(session)) return session;
  if (refreshInFlight) {
    const token = await refreshInFlight;
    if (!token) return null;
    return (
      (await readOpenAIOauthSession()) ?? { ...session, accessToken: token }
    );
  }
  refreshInFlight = refreshSession(session).finally(() => {
    refreshInFlight = null;
  });
  const token = await refreshInFlight;
  if (!token) return null;
  return (await readOpenAIOauthSession()) ?? { ...session, accessToken: token };
}

export async function resolveOpenAIOauthAccessToken(): Promise<string | null> {
  const session = await resolveOpenAIOauthSession();
  return session?.accessToken ?? null;
}
