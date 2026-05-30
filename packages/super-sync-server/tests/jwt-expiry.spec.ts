import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// Must set JWT_SECRET before auth.ts loads (getJwtSecret runs at module scope).
vi.hoisted(() => {
  process.env.JWT_SECRET = 'a'.repeat(32);
});

// The global setup.ts mocks '../src/auth' with a stub. We need the real
// getJwtExpiry, so override with importOriginal.
vi.mock('../src/auth', async (importOriginal) => {
  return await importOriginal();
});

vi.mock('../src/logger', () => ({
  Logger: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}));

import { getJwtExpiry } from '../src/auth';

describe('getJwtExpiry', () => {
  beforeEach(() => {
    delete process.env.JWT_EXPIRY;
  });

  afterEach(() => {
    delete process.env.JWT_EXPIRY;
  });

  it('defaults to 365d when JWT_EXPIRY is unset', () => {
    expect(getJwtExpiry()).toBe('365d');
  });

  it('defaults to 365d when JWT_EXPIRY is empty/whitespace', () => {
    process.env.JWT_EXPIRY = '   ';
    expect(getJwtExpiry()).toBe('365d');
  });

  it('passes through a valid timespan string', () => {
    process.env.JWT_EXPIRY = '7d';
    expect(getJwtExpiry()).toBe('7d');
  });

  it('trims surrounding whitespace', () => {
    process.env.JWT_EXPIRY = '  12h  ';
    expect(getJwtExpiry()).toBe('12h');
  });

  it('accepts various timespan units case-insensitively', () => {
    for (const value of ['90m', '6H', '1y', '2 days', '1.5h', '52w']) {
      process.env.JWT_EXPIRY = value;
      expect(getJwtExpiry()).toBe(value);
    }
  });

  it('coerces a bare integer to a number of seconds', () => {
    process.env.JWT_EXPIRY = '604800';
    // Returned as a number so jsonwebtoken treats it as seconds, not its
    // default of milliseconds.
    expect(getJwtExpiry()).toBe(604800);
  });

  it('throws on a non-positive integer', () => {
    process.env.JWT_EXPIRY = '0';
    expect(() => getJwtExpiry()).toThrow(/positive integer/);
  });

  it('throws on an unparseable value', () => {
    process.env.JWT_EXPIRY = 'forever';
    expect(() => getJwtExpiry()).toThrow(/Invalid JWT_EXPIRY/);
  });

  it('throws on a number without a recognized unit', () => {
    process.env.JWT_EXPIRY = '30 fortnights';
    expect(() => getJwtExpiry()).toThrow(/Invalid JWT_EXPIRY/);
  });
});
