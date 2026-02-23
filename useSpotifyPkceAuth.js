import { useCallback, useEffect, useMemo, useState } from "react";

const ACCOUNTS_BASE = "https://accounts.spotify.com";

const STORAGE = {
  verifier: "sp_pkce_code_verifier",
  state: "sp_pkce_state",
  token: "sp_access_token",
  tokenExpiresAt: "sp_access_token_expires_at",
};

function generateRandomString(length) {
  const possible =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  const values = crypto.getRandomValues(new Uint8Array(length));
  return values.reduce((acc, x) => acc + possible[x % possible.length], "");
}

// Spotify’s PKCE guide uses SHA-256 then base64-url encoding to form code_challenge. [page:1]
async function sha256(plain) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plain);
  return crypto.subtle.digest("SHA-256", data);
}

function base64UrlEncode(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

async function createCodeChallenge(verifier) {
  const hashed = await sha256(verifier);
  return base64UrlEncode(hashed);
}

function readQueryParams(search) {
  const p = new URLSearchParams(search);
  return {
    code: p.get("code"),
    error: p.get("error"),
    state: p.get("state"),
  };
}

export function useSpotifyPkceAuth({
  clientId,
  redirectUri,
  scope = "user-read-private user-read-email",
  // If you use React Router, pass location.search here for deterministic behavior.
  // Otherwise it defaults to window.location.search.
  search = typeof window !== "undefined" ? window.location.search : "",
  onAuthSuccess,
  onAuthError,
} = {}) {
  const [accessToken, setAccessToken] = useState(() => {
    return localStorage.getItem(STORAGE.token);
  });
  const [isAuthed, setIsAuthed] = useState(() => Boolean(accessToken));
  const [status, setStatus] = useState("idle"); // idle | redirecting | exchanging | authed | error
  const [error, setError] = useState(null);

  const expiresAt = useMemo(() => {
    const raw = localStorage.getItem(STORAGE.tokenExpiresAt);
    return raw ? Number(raw) : null;
  }, [accessToken]);

  const login = useCallback(async () => {
    try {
      setStatus("redirecting");
      setError(null);

      const codeVerifier = generateRandomString(64); // PKCE verifier should be 43–128 chars. [page:1]
      const codeChallenge = await createCodeChallenge(codeVerifier);
      const state = generateRandomString(16); // state is strongly recommended (CSRF protection). [page:1]

      localStorage.setItem(STORAGE.verifier, codeVerifier);
      localStorage.setItem(STORAGE.state, state);

      const authUrl = new URL(`${ACCOUNTS_BASE}/authorize`);
      authUrl.search = new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
        scope,
        code_challenge_method: "S256",
        code_challenge: codeChallenge,
        state,
      }).toString();

      window.location.assign(authUrl.toString());
    } catch (e) {
      setStatus("error");
      const msg = e instanceof Error ? e.message : String(e);
      setError(msg);
      onAuthError?.(msg);
    }
  }, [clientId, redirectUri, scope, onAuthError]);

  const logout = useCallback(() => {
    localStorage.removeItem(STORAGE.token);
    localStorage.removeItem(STORAGE.tokenExpiresAt);
    localStorage.removeItem(STORAGE.verifier);
    localStorage.removeItem(STORAGE.state);
    setAccessToken(null);
    setIsAuthed(false);
    setStatus("idle");
    setError(null);
  }, []);

  // Handle callback: parse code/error from URL and exchange code for token. [page:1]
  useEffect(() => {
    const { code, error: authError, state } = readQueryParams(search);
    if (!code && !authError) return;

    const expectedState = localStorage.getItem(STORAGE.state);
    if (expectedState && state && state !== expectedState) {
      setStatus("error");
      const msg = "State mismatch (possible CSRF or wrong session).";
      setError(msg);
      onAuthError?.(msg);
      return;
    }

    if (authError) {
      setStatus("error");
      setError(authError);
      onAuthError?.(authError);
      return;
    }

    (async () => {
      try {
        setStatus("exchanging");
        setError(null);

        const codeVerifier = localStorage.getItem(STORAGE.verifier);
        if (!codeVerifier) throw new Error("Missing code_verifier in storage.");

        // Token exchange is a POST to /api/token with application/x-www-form-urlencoded. [page:1]
        const res = await fetch(`${ACCOUNTS_BASE}/api/token`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id: clientId,
            grant_type: "authorization_code",
            code,
            redirect_uri: redirectUri,
            code_verifier: codeVerifier,
          }),
        });

        const json = await res.json();
        if (!res.ok) {
          throw new Error(
            json?.error_description ||
              json?.error?.message ||
              JSON.stringify(json)
          );
        }

        localStorage.setItem(STORAGE.token, json.access_token);

        // Spotify returns expires_in (seconds) in the token response. [page:1]
        const expiresAtMs = Date.now() + Number(json.expires_in) * 1000;
        localStorage.setItem(STORAGE.tokenExpiresAt, String(expiresAtMs));

        setAccessToken(json.access_token);
        setIsAuthed(true);
        setStatus("authed");

        // Optional: clear PKCE artifacts
        localStorage.removeItem(STORAGE.verifier);
        localStorage.removeItem(STORAGE.state);

        onAuthSuccess?.(json.access_token, json);
      } catch (e) {
        setStatus("error");
        const msg = e instanceof Error ? e.message : String(e);
        setError(msg);
        onAuthError?.(msg);
      }
    })();
  }, [search, clientId, redirectUri, onAuthSuccess, onAuthError]);

  const isExpired = expiresAt ? Date.now() > expiresAt : false;

  return {
    accessToken,
    isAuthed,
    isExpired,
    status,
    error,
    login,
    logout,
  };
}
