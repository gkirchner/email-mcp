import { expectedAuthToken, isAuthorized } from './http-auth.js';

const TOKEN = 'a'.repeat(64);

describe('expectedAuthToken', () => {
  it('returns undefined when the variable is unset', () => {
    expect(expectedAuthToken({})).toBeUndefined();
  });

  it('returns undefined when the variable is empty', () => {
    expect(expectedAuthToken({ MCP_AUTH_TOKEN: '' })).toBeUndefined();
  });

  it('returns undefined when the variable is only whitespace', () => {
    expect(expectedAuthToken({ MCP_AUTH_TOKEN: '   ' })).toBeUndefined();
  });

  it('returns the bare token', () => {
    expect(expectedAuthToken({ MCP_AUTH_TOKEN: TOKEN })).toBe(TOKEN);
  });

  it('trims surrounding whitespace', () => {
    expect(expectedAuthToken({ MCP_AUTH_TOKEN: `  ${TOKEN}  ` })).toBe(TOKEN);
  });

  it('tolerates a pasted "Bearer " prefix', () => {
    expect(expectedAuthToken({ MCP_AUTH_TOKEN: `Bearer ${TOKEN}` })).toBe(TOKEN);
  });

  it('tolerates a pasted prefix in any case', () => {
    expect(expectedAuthToken({ MCP_AUTH_TOKEN: `bearer ${TOKEN}` })).toBe(TOKEN);
  });

  it('returns undefined when the variable is only a prefix', () => {
    expect(expectedAuthToken({ MCP_AUTH_TOKEN: 'Bearer ' })).toBeUndefined();
  });
});

describe('isAuthorized', () => {
  describe('when no token is configured', () => {
    it('allows a request without a header', () => {
      expect(isAuthorized(undefined, undefined)).toBe(true);
    });

    it('allows a request with an arbitrary header', () => {
      expect(isAuthorized('Bearer whatever', undefined)).toBe(true);
    });
  });

  describe('when a token is configured', () => {
    it('accepts the matching token', () => {
      expect(isAuthorized(`Bearer ${TOKEN}`, TOKEN)).toBe(true);
    });

    it('accepts a lowercase scheme', () => {
      expect(isAuthorized(`bearer ${TOKEN}`, TOKEN)).toBe(true);
    });

    it('accepts extra whitespace around the header', () => {
      expect(isAuthorized(`  Bearer   ${TOKEN}  `, TOKEN)).toBe(true);
    });

    it('rejects a missing header', () => {
      expect(isAuthorized(undefined, TOKEN)).toBe(false);
    });

    it('rejects an empty header', () => {
      expect(isAuthorized('', TOKEN)).toBe(false);
    });

    it('rejects a wrong token of the same length', () => {
      expect(isAuthorized(`Bearer ${'b'.repeat(64)}`, TOKEN)).toBe(false);
    });

    it('rejects a wrong token of a different length', () => {
      expect(isAuthorized('Bearer short', TOKEN)).toBe(false);
    });

    it('rejects a token that is only a prefix of the expected one', () => {
      expect(isAuthorized(`Bearer ${TOKEN.slice(0, 32)}`, TOKEN)).toBe(false);
    });

    it('rejects the bare token without the Bearer scheme', () => {
      expect(isAuthorized(TOKEN, TOKEN)).toBe(false);
    });

    it('rejects a different auth scheme carrying the token', () => {
      expect(isAuthorized(`Basic ${TOKEN}`, TOKEN)).toBe(false);
    });

    it('rejects a header with the scheme but no token', () => {
      expect(isAuthorized('Bearer ', TOKEN)).toBe(false);
    });

    it('rejects a bare scheme with no separator', () => {
      expect(isAuthorized('Bearer', TOKEN)).toBe(false);
    });

    // Node lowercases and joins repeated request headers, but the type allows an
    // array, so the first entry is what a proxy would forward.
    it('uses the first entry when the header repeats', () => {
      expect(isAuthorized([`Bearer ${TOKEN}`, 'Bearer nope'], TOKEN)).toBe(true);
    });

    it('rejects when the first repeated entry is wrong', () => {
      expect(isAuthorized(['Bearer nope', `Bearer ${TOKEN}`], TOKEN)).toBe(false);
    });

    it('rejects an empty header array', () => {
      expect(isAuthorized([], TOKEN)).toBe(false);
    });
  });
});

describe('expectedAuthToken — token that begins with the scheme letters', () => {
  it('keeps a token like "Bearertoken" intact', () => {
    expect(expectedAuthToken({ MCP_AUTH_TOKEN: 'Bearertoken' })).toBe('Bearertoken');
  });
});
