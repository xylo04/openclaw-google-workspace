/**
 * Shared OAuth2 authentication service for all Google Workspace services.
 * Single credential file, single token file, scopes computed from enabled services.
 *
 * Adapted from the Calendar plugin's google-calendar-auth.ts, generalized for multi-service use.
 */

import { google } from "googleapis";
import type { OAuth2Client, Credentials } from "google-auth-library";
import { readFile, open, rename, access } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { resolve, dirname } from "node:path";
import { randomBytes } from "node:crypto";

import type { ResolvedWorkspaceConfig } from "../config/schema.js";
import {
  AuthenticationRequiredError,
  PluginConfigurationError,
} from "../shared/errors.js";

// ---------------------------------------------------------------------------
// Scope mapping
// ---------------------------------------------------------------------------

const SCOPE_BASE = "https://www.googleapis.com/auth/";

export function getRequiredScopes(config: ResolvedWorkspaceConfig): string[] {
  const scopes: string[] = [];
  const s = config.services;

  if (s.gmail.enabled) {
    if (s.gmail.readOnly) {
      scopes.push(`${SCOPE_BASE}gmail.readonly`);
    } else {
      scopes.push(`${SCOPE_BASE}gmail.modify`);
      scopes.push(`${SCOPE_BASE}gmail.send`);
    }
  }

  if (s.calendar.enabled) {
    scopes.push(
      s.calendar.readOnly
        ? `${SCOPE_BASE}calendar.events.readonly`
        : `${SCOPE_BASE}calendar.events`,
    );
  }

  if (s.drive.enabled) {
    scopes.push(
      s.drive.readOnly
        ? `${SCOPE_BASE}drive.readonly`
        : `${SCOPE_BASE}drive.file`,
    );
  }

  if (s.contacts.enabled) {
    scopes.push(`${SCOPE_BASE}contacts.readonly`);
  }

  if (s.tasks.enabled) {
    scopes.push(`${SCOPE_BASE}tasks`);
  }

  if (s.sheets.enabled) {
    scopes.push(
      s.sheets.readOnly
        ? `${SCOPE_BASE}spreadsheets.readonly`
        : `${SCOPE_BASE}spreadsheets`,
    );
  }

  return scopes;
}

// ---------------------------------------------------------------------------
// Credential file loading
// ---------------------------------------------------------------------------

interface OAuthClientCredentials {
  client_id: string;
  client_secret: string;
  redirect_uris?: string[];
}

async function loadCredentials(
  credentialsPath: string,
): Promise<OAuthClientCredentials> {
  let raw: string;
  try {
    raw = await readFile(credentialsPath, "utf-8");
  } catch {
    throw new PluginConfigurationError(
      `Cannot read OAuth credentials file at: ${credentialsPath}\n` +
        `Download the OAuth Desktop Client JSON from your Google Cloud Console ` +
        `and place it at the configured credentialsPath.`,
    );
  }

  let json: Record<string, unknown>;
  try {
    json = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    throw new PluginConfigurationError(
      `Invalid JSON in credentials file at: ${credentialsPath}`,
    );
  }

  // Google credential files have "installed" or "web" wrapper
  const inner =
    (json.installed as OAuthClientCredentials | undefined) ??
    (json.web as OAuthClientCredentials | undefined);

  if (!inner?.client_id || !inner?.client_secret) {
    throw new PluginConfigurationError(
      `Credentials file at ${credentialsPath} is missing client_id or client_secret. ` +
        `Ensure you downloaded the OAuth 2.0 Client ID JSON (not a service account key).`,
    );
  }

  return inner;
}

// ---------------------------------------------------------------------------
// Token persistence
// ---------------------------------------------------------------------------

async function readStoredTokens(
  tokenPath: string,
): Promise<Credentials | null> {
  try {
    const raw = await readFile(tokenPath, "utf-8");
    return JSON.parse(raw) as Credentials;
  } catch {
    return null;
  }
}

async function writeTokens(
  tokenPath: string,
  tokens: Credentials,
): Promise<void> {
  const absPath = resolve(tokenPath);
  const tmpPath = `${absPath}.${randomBytes(4).toString("hex")}.tmp`;
  const tmpFile = await open(tmpPath, "wx", 0o600);
  try {
    await tmpFile.writeFile(JSON.stringify(tokens, null, 2), "utf-8");
  } finally {
    await tmpFile.close();
  }
  await rename(tmpPath, absPath);
}

async function tokenFileExists(tokenPath: string): Promise<boolean> {
  try {
    await access(tokenPath, fsConstants.R_OK);
    return true;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Auth service
// ---------------------------------------------------------------------------

export interface AuthorizationRequest {
  url: string;
  scopes: string[];
  enabledServices: string[];
}

export interface GoogleWorkspaceAuthService {
  createAuthorizationUrl(): Promise<AuthorizationRequest>;
  exchangeCodeForToken(code: string): Promise<void>;
  hasStoredToken(): Promise<boolean>;
  createAuthenticatedClient(): Promise<OAuth2Client>;
  getRequiredScopes(): string[];
  getEnabledServices(): string[];
  checkScopeGaps(): Promise<{ authorized: string[]; missing: string[] } | null>;
}

export function createAuthService(
  config: ResolvedWorkspaceConfig,
): GoogleWorkspaceAuthService {
  const credentialsPath = config.credentialsPath;
  const tokenPath = config.tokenPath;

  if (!credentialsPath) {
    throw new PluginConfigurationError(
      "credentialsPath is required. Set it in plugin config or via GOOGLE_WORKSPACE_CREDENTIALS_PATH.",
    );
  }
  if (!tokenPath) {
    throw new PluginConfigurationError(
      "tokenPath is required. Set it in plugin config or via GOOGLE_WORKSPACE_TOKEN_PATH.",
    );
  }

  const scopes = getRequiredScopes(config);

  const enabledServices = Object.entries(config.services)
    .filter(([, svc]) => svc.enabled)
    .map(([name]) => name);

  let cachedClient: OAuth2Client | null = null;

  async function getOAuth2Client(): Promise<OAuth2Client> {
    const creds = await loadCredentials(credentialsPath!);
    const redirectUri =
      config.oauthRedirectUri ??
      creds.redirect_uris?.[0] ??
      "http://127.0.0.1:3000/oauth2callback";

    return new google.auth.OAuth2(
      creds.client_id,
      creds.client_secret,
      redirectUri,
    );
  }

  return {
    getRequiredScopes() {
      return scopes;
    },

    getEnabledServices() {
      return enabledServices;
    },

    async createAuthorizationUrl(): Promise<AuthorizationRequest> {
      const client = await getOAuth2Client();
      const url = client.generateAuthUrl({
        access_type: "offline",
        scope: scopes,
        prompt: "consent",
        include_granted_scopes: true,
      });
      return { url, scopes, enabledServices };
    },

    async exchangeCodeForToken(code: string): Promise<void> {
      const client = await getOAuth2Client();
      const { tokens } = await client.getToken(code);

      // Merge with existing tokens to preserve refresh_token if Google only returns access_token
      const existing = await readStoredTokens(tokenPath!);
      const merged: Credentials = {
        ...existing,
        ...tokens,
      };
      // Preserve existing refresh_token if the new response doesn't include one
      if (!merged.refresh_token && existing?.refresh_token) {
        merged.refresh_token = existing.refresh_token;
      }

      await writeTokens(tokenPath!, merged);
    },

    async hasStoredToken(): Promise<boolean> {
      return tokenFileExists(tokenPath!);
    },

    async createAuthenticatedClient(): Promise<OAuth2Client> {
      if (cachedClient) return cachedClient;

      const tokens = await readStoredTokens(tokenPath!);
      if (!tokens) {
        throw new AuthenticationRequiredError(
          "No stored OAuth tokens found. Run google_workspace_begin_auth to authorize.",
        );
      }

      const client = await getOAuth2Client();
      client.setCredentials(tokens);

      // Auto-refresh: persist new tokens when Google refreshes them
      client.on("tokens", (newTokens) => {
        const merged: Credentials = { ...tokens, ...newTokens };
        if (!merged.refresh_token && tokens.refresh_token) {
          merged.refresh_token = tokens.refresh_token;
        }
        writeTokens(tokenPath!, merged).catch(() => {
          // Token write failure is non-fatal — next call will re-refresh
        });
      });

      cachedClient = client;
      return client;
    },

    async checkScopeGaps(): Promise<{
      authorized: string[];
      missing: string[];
    } | null> {
      const tokens = await readStoredTokens(tokenPath!);
      if (!tokens) return null;

      const granted = tokens.scope?.split(" ") ?? [];
      const authorized = scopes.filter((s) => granted.includes(s));
      const missing = scopes.filter((s) => !granted.includes(s));
      return { authorized, missing };
    },
  };
}
