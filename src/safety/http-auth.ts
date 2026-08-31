/**
 * Bearer-token authentication for the Streamable HTTP transport.
 *
 * The `stdio` transport is reachable only by the process that spawned it, but
 * `http` binds 0.0.0.0 — on a hosted deploy that is the open internet, and every
 * tool this server exposes reads or sends mail. Without a check on `/mcp` the
 * endpoint is an open relay for whoever learns the URL.
 */

import { createHash, timingSafeEqual } from 'node:crypto';

/**
 * Compare two secrets without leaking their contents through timing.
 *
 * Hashing first gives both sides a fixed 32-byte length, which `timingSafeEqual`
 * requires — comparing the raw strings would throw on a length mismatch and so
 * reveal the expected token's length.
 */
function secretsMatch(a: string, b: string): boolean {
  const digest = (v: string): Buffer => createHash('sha256').update(v, 'utf8').digest();
  return timingSafeEqual(digest(a), digest(b));
}

/**
 * The token every `/mcp` request must present, or `undefined` when no token is
 * configured and the endpoint is deliberately left open.
 *
 * A `Bearer ` prefix in the variable itself is tolerated: pasting the whole
 * header value here is an easy mistake, and rejecting it would lock the operator
 * out of their own server for a reason invisible from the outside.
 */
export function expectedAuthToken(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const raw = env.MCP_AUTH_TOKEN?.trim();
  if (raw === undefined || raw === '') return undefined;
  // `\b[ \t]*` rather than `[ ]+` so that a lone "Bearer" reduces to the empty
  // string (and thus to "no token") instead of becoming the literal token
  // "Bearer", while a real token that merely starts with those letters — say
  // "Bearertoken" — has no word boundary there and survives untouched.
  const token = raw.replace(/^Bearer\b[ \t]*/i, '').trim();
  return token === '' ? undefined : token;
}

/**
 * Check the `Authorization` header of a request to `/mcp`.
 *
 * Returns true unconditionally when `expected` is `undefined`, so an operator who
 * sets no token keeps the previous open behaviour — the startup banner says so
 * out loud rather than failing silently.
 */
export function isAuthorized(
  header: string | string[] | undefined,
  expected: string | undefined,
): boolean {
  if (expected === undefined) return true;
  const raw = Array.isArray(header) ? header[0] : header;
  if (typeof raw !== 'string') return false;
  const match = /^Bearer[ ]+(\S.*)$/i.exec(raw.trim());
  if (match === null) return false;
  return secretsMatch(match[1].trim(), expected);
}
