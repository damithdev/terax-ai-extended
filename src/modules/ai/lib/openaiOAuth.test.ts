import { describe, expect, it } from "vitest";
import {
  credentialsFromTokenResponse,
  emailFromIdToken,
  extractAccountId,
  isOpenAIApiKey,
  OPENAI_OAUTH_ACCOUNT,
  OPENAI_OAUTH_REFRESH_SKEW_MS,
  parseDeviceGrant,
  parseDeviceUserCode,
  parseOAuthSession,
  sessionFromCredentialMap,
  sessionNeedsRefresh,
  sessionToCredentialEntries,
  WIN_CREDENTIAL_MAX_CHARS,
} from "./openaiOAuth";

function jwtFromPayload(payload: Record<string, unknown>): string {
  const encode = (value: object) => {
    const json = JSON.stringify(value);
    return btoa(json)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, "");
  };
  return `${encode({ alg: "none", typ: "JWT" })}.${encode(payload)}.sig`;
}

const validSession = {
  accessToken: "access-1",
  refreshToken: "refresh-1",
  expiresAt: 1_700_000_000_000,
  accountId: "acct-1",
  email: "user@example.com",
  name: "Ada",
};

describe("isOpenAIApiKey", () => {
  it("accepts platform keys and rejects JWTs", () => {
    expect(isOpenAIApiKey("sk-proj-abc")).toBe(true);
    expect(isOpenAIApiKey("sk-abc")).toBe(true);
    expect(isOpenAIApiKey("eyJhbGciOiJIUzI1NiJ9.e30.sig")).toBe(false);
    expect(isOpenAIApiKey(null)).toBe(false);
  });
});

describe("parseOAuthSession", () => {
  it("accepts a complete session object and JSON string", () => {
    expect(parseOAuthSession(validSession)).toEqual(validSession);
    expect(parseOAuthSession(JSON.stringify(validSession))).toEqual(
      validSession,
    );
  });

  it("rejects missing tokens", () => {
    expect(parseOAuthSession({ accessToken: "a", expiresAt: 1 })).toBeNull();
  });
});

describe("sessionNeedsRefresh", () => {
  it("is true within two minutes of expiry", () => {
    const now = 1_000_000;
    expect(
      sessionNeedsRefresh(
        { expiresAt: now + OPENAI_OAUTH_REFRESH_SKEW_MS },
        now,
      ),
    ).toBe(true);
    expect(
      sessionNeedsRefresh(
        { expiresAt: now + OPENAI_OAUTH_REFRESH_SKEW_MS + 1 },
        now,
      ),
    ).toBe(false);
  });
});

describe("extractAccountId and emailFromIdToken", () => {
  it("reads chatgpt_account_id from the namespaced auth claim", () => {
    const token = jwtFromPayload({
      email: "a@x.com",
      name: "Ada",
      "https://api.openai.com/auth": { chatgpt_account_id: "acct-9" },
    });
    expect(extractAccountId(token)).toBe("acct-9");
    expect(emailFromIdToken(token)).toBe("a@x.com");
  });

  it("falls back to a top-level chatgpt_account_id", () => {
    expect(
      extractAccountId(jwtFromPayload({ chatgpt_account_id: "acct-top" })),
    ).toBe("acct-top");
  });
});

describe("parseDeviceUserCode and parseDeviceGrant", () => {
  it("accepts user_code or usercode", () => {
    expect(
      parseDeviceUserCode({
        device_auth_id: "did",
        user_code: "ABCD-EFGH",
        interval: 5,
      }),
    ).toEqual({
      deviceAuthId: "did",
      userCode: "ABCD-EFGH",
      intervalMs: 5000,
    });
    expect(
      parseDeviceUserCode({
        device_auth_id: "did",
        usercode: "ZZZZ",
      })?.userCode,
    ).toBe("ZZZZ");
  });

  it("requires authorization_code and code_verifier", () => {
    expect(
      parseDeviceGrant({
        authorization_code: "ac",
        code_verifier: "cv",
      }),
    ).toEqual({ authorizationCode: "ac", codeVerifier: "cv" });
    expect(parseDeviceGrant({ authorization_code: "ac" })).toBeNull();
  });
});

describe("credentialsFromTokenResponse", () => {
  it("maps tokens and derives account id from the id_token", () => {
    const now = 5_000;
    const idToken = jwtFromPayload({
      email: "a@x.com",
      chatgpt_account_id: "acct-1",
    });
    expect(
      credentialsFromTokenResponse(
        {
          access_token: "at",
          refresh_token: "rt",
          expires_in: 30,
          id_token: idToken,
        },
        undefined,
        now,
      ),
    ).toEqual({
      accessToken: "at",
      refreshToken: "rt",
      expiresAt: now + 30_000,
      accountId: "acct-1",
      email: "a@x.com",
    });
  });

  it("keeps the previous refresh token when omitted", () => {
    const now = 10_000;
    expect(
      credentialsFromTokenResponse(
        { access_token: "new-at", expires_in: 10 },
        { refreshToken: "old-rt", accountId: "acct-1", email: "kept@x.com" },
        now,
      ),
    ).toEqual({
      accessToken: "new-at",
      refreshToken: "old-rt",
      expiresAt: now + 10_000,
      accountId: "acct-1",
      email: "kept@x.com",
    });
  });
});

describe("session credential split", () => {
  function bigToken(size: number, seed: string): string {
    return seed.repeat(Math.ceil(size / seed.length)).slice(0, size);
  }

  it("keeps each Windows credential under the UTF-16 byte cap", () => {
    const session = {
      accessToken: bigToken(1800, "a"),
      refreshToken: bigToken(1800, "r"),
      expiresAt: 99,
      accountId: "acct-1",
      email: "user@example.com",
    };
    const packed = JSON.stringify({
      ...session,
      idToken: bigToken(800, "i"),
    });
    expect(packed.length).toBeGreaterThan(WIN_CREDENTIAL_MAX_CHARS);
    const entries = sessionToCredentialEntries(session);
    expect(
      entries.every((e) => e.password.length <= WIN_CREDENTIAL_MAX_CHARS),
    ).toBe(true);
    const map = Object.fromEntries(entries.map((e) => [e.account, e.password]));
    expect(sessionFromCredentialMap(map)).toEqual(session);
    expect(map[OPENAI_OAUTH_ACCOUNT]).not.toContain("accessToken");
  });

  it("chunks a ChatGPT token that fits 2560 chars but exceeds the 1280 UTF-16 cap", () => {
    const session = {
      accessToken: bigToken(2000, "a"),
      refreshToken: bigToken(2000, "r"),
      expiresAt: 1,
    };
    const entries = sessionToCredentialEntries(session);
    expect(entries.length).toBeGreaterThan(3);
    expect(
      entries.every((e) => e.password.length <= WIN_CREDENTIAL_MAX_CHARS),
    ).toBe(true);
    const map = Object.fromEntries(entries.map((e) => [e.account, e.password]));
    expect(sessionFromCredentialMap(map)?.accessToken).toBe(
      session.accessToken,
    );
    expect(sessionFromCredentialMap(map)?.refreshToken).toBe(
      session.refreshToken,
    );
  });

  it("chunks a single token that itself exceeds the cap", () => {
    const session = {
      accessToken: bigToken(WIN_CREDENTIAL_MAX_CHARS + 40, "a"),
      refreshToken: "rt",
      expiresAt: 1,
    };
    const entries = sessionToCredentialEntries(session);
    expect(
      entries.every((e) => e.password.length <= WIN_CREDENTIAL_MAX_CHARS),
    ).toBe(true);
    const map = Object.fromEntries(entries.map((e) => [e.account, e.password]));
    expect(sessionFromCredentialMap(map)?.accessToken).toBe(
      session.accessToken,
    );
  });
});
