import { prisma } from './db';
import * as jwt from 'jsonwebtoken';
const { JsonWebTokenError, TokenExpiredError } = jwt;
import { Logger } from './logger';
import { randomBytes } from 'crypto';
import { sendLoginMagicLinkEmail, sendVerificationEmail } from './email';
import { loadConfigFromEnv } from './config';
import { Prisma } from '@prisma/client';
import { authCache } from './auth-cache';

// Auth constants
const MIN_JWT_SECRET_LENGTH = 32;

// JWT lifetime. Tokens live for 365 days by default regardless of authentication
// method — the auth method (passkey, magic link) only matters during login; once
// a JWT is issued, it represents a verified session. Self-hosted deployments can
// override this with the JWT_EXPIRY env var (e.g. a shorter session on shared
// machines) without rebuilding the image.
const DEFAULT_JWT_EXPIRY = '365d';

// Accepted JWT_EXPIRY timespan units (vercel/ms syntax), e.g. "365d", "12h", "90m".
// Bare integers are handled separately and treated as seconds.
const JWT_EXPIRY_TIMESPAN_RE =
  /^\d+(?:\.\d+)?\s*(?:years?|yrs?|y|weeks?|w|days?|d|hours?|hrs?|h|minutes?|mins?|m|seconds?|secs?|s|milliseconds?|msecs?|ms)$/i;

/** The validated `expiresIn` value jsonwebtoken accepts (timespan string or seconds). */
type JwtExpiry = NonNullable<jwt.SignOptions['expiresIn']>;

/**
 * Resolve the JWT lifetime from the JWT_EXPIRY env var, falling back to 365 days.
 *
 * Accepts either a positive integer number of seconds (e.g. "604800") or a
 * vercel/ms timespan string (e.g. "365d", "12h", "90m"). A bare integer is
 * coerced to a number so jsonwebtoken treats it as seconds rather than its
 * default of milliseconds. Invalid values throw at startup so a typo fails fast
 * instead of surfacing later at token-signing time.
 */
export const getJwtExpiry = (): JwtExpiry => {
  const raw = process.env.JWT_EXPIRY?.trim();
  if (!raw) {
    return DEFAULT_JWT_EXPIRY;
  }
  if (/^\d+$/.test(raw)) {
    const seconds = parseInt(raw, 10);
    if (seconds <= 0) {
      throw new Error(`Invalid JWT_EXPIRY "${raw}": seconds must be a positive integer.`);
    }
    return seconds;
  }
  if (!JWT_EXPIRY_TIMESPAN_RE.test(raw)) {
    throw new Error(
      `Invalid JWT_EXPIRY "${raw}": use a positive number of seconds (e.g. "604800") ` +
        `or a timespan string such as "365d", "12h" or "90m".`,
    );
  }
  return raw as JwtExpiry;
};

export const JWT_EXPIRY = getJwtExpiry();

export const VERIFICATION_TOKEN_EXPIRY_MS = 24 * 60 * 60 * 1000; // 24 hours
export const MAX_VERIFICATION_RESEND_COUNT = 20;
const LOGIN_MAGIC_LINK_EXPIRY_MS = 15 * 60 * 1000; // 15 minutes

export const getJwtSecret = (): string => {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error(
      'JWT_SECRET environment variable is required. ' +
        `Generate one with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`,
    );
  }
  if (secret.length < MIN_JWT_SECRET_LENGTH) {
    throw new Error(
      `JWT_SECRET must be at least ${MIN_JWT_SECRET_LENGTH} characters for security`,
    );
  }
  return secret;
};

const JWT_SECRET = getJwtSecret();

export const verifyEmail = async (token: string): Promise<boolean> => {
  const user = await prisma.user.findFirst({
    where: { verificationToken: token },
  });

  if (!user) {
    throw new Error('Invalid verification token');
  }

  if (
    user.verificationTokenExpiresAt &&
    user.verificationTokenExpiresAt < BigInt(Date.now())
  ) {
    throw new Error('Verification token has expired');
  }

  await prisma.user.update({
    where: { id: user.id },
    data: {
      isVerified: 1,
      verificationToken: null,
      verificationTokenExpiresAt: null,
      verificationResendCount: 0,
    },
  });

  // AUTH_CACHE_INVALIDATION: drop any negative (isVerified:false) entry so the
  // now-verified user isn't denied for up to the cache TTL, and so the cache
  // stays correct if a verified -> unverified path is ever added.
  authCache.invalidate(user.id);

  Logger.info(`User verified (ID: ${user.id})`);
  return true;
};

/**
 * Revoke all existing tokens for a user by incrementing their token version.
 * Call this when the user explicitly logs out all devices.
 */
export const revokeAllTokens = async (userId: number): Promise<void> => {
  // AUTH_CACHE_INVALIDATION: keep adjacent to tokenVersion writes.
  authCache.invalidate(userId);
  await prisma.user.update({
    where: { id: userId },
    data: { tokenVersion: { increment: 1 } },
  });
  // AUTH_CACHE_INVALIDATION: keep adjacent to tokenVersion writes.
  authCache.invalidate(userId);
  Logger.info(`All tokens revoked for user ${userId}`);
};

/**
 * Replace the current JWT with a new one.
 * This invalidates all existing tokens (including the current one) and returns a fresh token.
 */
export const replaceToken = async (
  userId: number,
  email: string,
): Promise<{ token: string; user: { id: number; email: string } }> => {
  // AUTH_CACHE_INVALIDATION: keep adjacent to tokenVersion writes.
  authCache.invalidate(userId);
  // Use transaction to ensure atomicity of version increment and read
  const newTokenVersion = await prisma.$transaction(async (tx) => {
    // Increment token version to invalidate all existing tokens
    const user = await tx.user.update({
      where: { id: userId },
      data: { tokenVersion: { increment: 1 } },
      select: { tokenVersion: true },
    });
    return user.tokenVersion;
  });
  // AUTH_CACHE_INVALIDATION: keep adjacent to tokenVersion writes.
  authCache.invalidate(userId);

  const token = jwt.sign({ userId, email, tokenVersion: newTokenVersion }, JWT_SECRET, {
    expiresIn: JWT_EXPIRY,
  });

  Logger.info(`Token replaced for user ${userId} (new version: ${newTokenVersion})`);

  return { token, user: { id: userId, email } };
};

export type TokenVerificationResult =
  | { valid: true; userId: number; email: string }
  | { valid: false; reason: string };

export const verifyToken = async (token: string): Promise<TokenVerificationResult> => {
  try {
    const payload = await new Promise<{
      userId: number;
      email: string;
      tokenVersion?: number;
    }>((resolve, reject) => {
      jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return reject(err);
        resolve(decoded as { userId: number; email: string; tokenVersion?: number });
      });
    });

    const tokenVersion = payload.tokenVersion ?? 0;
    const cachedUser = authCache.get(payload.userId);
    if (cachedUser && cachedUser.isVerified && cachedUser.tokenVersion === tokenVersion) {
      return { valid: true, userId: payload.userId, email: payload.email };
    }
    const cacheVersionBeforeRead = authCache.getInvalidationVersion(payload.userId);

    // Verify user exists, is verified, and token version matches
    const user = await prisma.user.findUnique({
      where: { id: payload.userId },
      select: { id: true, tokenVersion: true, isVerified: true },
    });

    if (!user) {
      Logger.warn(`Token verification failed: User ${payload.userId} not found in DB`);
      return { valid: false, reason: 'Account unavailable' };
    }

    if (!user.isVerified) {
      Logger.warn(`Token verification failed: User ${payload.userId} is not verified`);
      authCache.setIfCurrent(
        payload.userId,
        user.tokenVersion ?? 0,
        false,
        cacheVersionBeforeRead,
      );
      return { valid: false, reason: 'Account unavailable' };
    }

    // Check token version - if it doesn't match, the token has been revoked
    // (e.g., user used "Revoke & Replace Token"). Tokens without version are treated as version 0.
    const currentVersion = user.tokenVersion ?? 0;
    if (tokenVersion !== currentVersion) {
      Logger.warn(
        `Token verification failed: Token version mismatch for user ${payload.userId} ` +
          `(token: ${tokenVersion}, current: ${currentVersion})`,
      );
      return {
        valid: false,
        reason: 'Token was revoked. Please log in again to get a new token.',
      };
    }

    authCache.setIfCurrent(payload.userId, currentVersion, true, cacheVersionBeforeRead);
    return { valid: true, userId: payload.userId, email: payload.email };
  } catch (err) {
    if (err instanceof TokenExpiredError) {
      return {
        valid: false,
        reason: 'Token expired. Please log in again to get a new token.',
      };
    }
    // Only treat actual JWT errors as "Invalid token" (NotBeforeError extends JsonWebTokenError).
    // Database errors must propagate as 500s, not masquerade as auth failures.
    if (err instanceof JsonWebTokenError) {
      return { valid: false, reason: 'Invalid token' };
    }
    const errMsg =
      err instanceof Error ? `[${err.name}] ${err.message}` : 'non-Error value';
    Logger.error(`Token verification failed due to unexpected error: ${errMsg}`);
    throw err;
  }
};

/**
 * Request a magic link for passwordless login.
 * Generates a login token, stores it in the database, and sends an email.
 * Always returns success message to prevent email enumeration.
 */
export const requestLoginMagicLink = async (
  email: string,
): Promise<{ message: string }> => {
  const successMessage = {
    message: 'If an account with that email exists, a login link has been sent.',
  };

  const user = await prisma.user.findUnique({
    where: { email: email.toLowerCase() },
  });

  if (!user) {
    Logger.debug(`Magic link requested for non-existent email`);
    return successMessage;
  }

  if (user.isVerified === 0) {
    Logger.debug(`Magic link requested for unverified account (ID: ${user.id})`);
    return successMessage;
  }

  const loginToken = randomBytes(32).toString('hex');
  const expiresAt = BigInt(Date.now() + LOGIN_MAGIC_LINK_EXPIRY_MS);

  await prisma.user.update({
    where: { id: user.id },
    data: {
      loginToken,
      loginTokenExpiresAt: expiresAt,
    },
  });

  const emailSent = await sendLoginMagicLinkEmail(email, loginToken);
  if (!emailSent) {
    await prisma.user.update({
      where: { id: user.id },
      data: {
        loginToken: null,
        loginTokenExpiresAt: null,
      },
    });
    throw new Error('Failed to send login email. Please try again later.');
  }

  Logger.info(`Magic link login requested (ID: ${user.id})`);
  return successMessage;
};

/**
 * Verify a magic link login token and return a JWT.
 */
export const verifyLoginMagicLink = async (
  token: string,
): Promise<{ token: string; user: { id: number; email: string } }> => {
  const user = await prisma.user.findFirst({
    where: { loginToken: token },
  });

  if (!user) {
    throw new Error('Invalid or expired login link');
  }

  if (user.loginTokenExpiresAt && user.loginTokenExpiresAt < BigInt(Date.now())) {
    await prisma.user.update({
      where: { id: user.id },
      data: {
        loginToken: null,
        loginTokenExpiresAt: null,
      },
    });
    throw new Error('Invalid or expired login link');
  }

  // Clear the token (single use) and reset any failed attempts
  await prisma.user.update({
    where: { id: user.id },
    data: {
      loginToken: null,
      loginTokenExpiresAt: null,
      failedLoginAttempts: 0,
      lockedUntil: null,
    },
  });

  const tokenVersion = user.tokenVersion ?? 0;
  const jwtToken = jwt.sign(
    { userId: user.id, email: user.email, tokenVersion },
    JWT_SECRET,
    { expiresIn: JWT_EXPIRY },
  );

  Logger.info(`User logged in via magic link (ID: ${user.id})`);

  return { token: jwtToken, user: { id: user.id, email: user.email } };
};

/**
 * Register a new user via magic link (email-only, no passkey required).
 * Sends a verification email. User can then log in via magic link after verifying.
 */
export const registerWithMagicLink = async (
  email: string,
  termsAcceptedAt?: number,
): Promise<{ message: string }> => {
  const normalizedEmail = email.toLowerCase();

  // Check if email already exists and is verified
  const existingUser = await prisma.user.findUnique({
    where: { email: normalizedEmail },
  });

  if (existingUser?.isVerified === 1) {
    throw new Error('An account with this email already exists');
  }

  const verificationToken = randomBytes(32).toString('hex');
  const tokenExpiresAt = BigInt(Date.now() + VERIFICATION_TOKEN_EXPIRY_MS);
  const acceptedAt = termsAcceptedAt !== undefined ? BigInt(termsAcceptedAt) : undefined;

  try {
    // In TEST_MODE with autoVerifyUsers, skip email and auto-verify
    const config = loadConfigFromEnv();

    if (existingUser) {
      if (existingUser.verificationResendCount >= MAX_VERIFICATION_RESEND_COUNT) {
        throw new Error(
          'Too many verification attempts. Please try again later or contact support.',
        );
      }

      if (!config.testMode?.autoVerifyUsers) {
        // Send email BEFORE updating DB to avoid invalidating the old token on failure
        const emailSent = await sendVerificationEmail(normalizedEmail, verificationToken);
        if (!emailSent) {
          throw new Error('Failed to send verification email. Please try again later.');
        }
      }

      // Update existing unverified user with new verification token
      await prisma.user.update({
        where: { id: existingUser.id },
        data: {
          verificationToken,
          verificationTokenExpiresAt: tokenExpiresAt,
          verificationResendCount: { increment: 1 },
          ...(acceptedAt !== undefined && { termsAcceptedAt: acceptedAt }),
        },
      });

      Logger.info(
        `Updated verification token for unverified user (ID: ${existingUser.id})`,
      );
    } else {
      // Create new user (no passkey, no password)
      await prisma.user.create({
        data: {
          email: normalizedEmail,
          passwordHash: null,
          verificationToken,
          verificationTokenExpiresAt: tokenExpiresAt,
          termsAcceptedAt: acceptedAt ?? BigInt(Date.now()),
        },
      });

      Logger.info(`Created new magic-link user`);

      if (!config.testMode?.autoVerifyUsers) {
        // Send verification email; clean up new user on failure
        const emailSent = await sendVerificationEmail(normalizedEmail, verificationToken);
        if (!emailSent) {
          // AUTH_CACHE_INVALIDATION: no invalidate needed here. This only
          // deletes the user just created above (isVerified: 0). No JWT is
          // issued for an unverified user, so verifyToken was never called for
          // it and no authCache entry can exist. Documented to keep the
          // bracket-every-delete convention auditable.
          await prisma.user.deleteMany({
            where: { email: normalizedEmail, isVerified: 0 },
          });
          Logger.info(`Cleaned up failed magic-link registration for new user`);
          throw new Error('Failed to send verification email. Please try again later.');
        }
      }
    }

    if (config.testMode?.autoVerifyUsers) {
      await prisma.user.update({
        where: { email: normalizedEmail },
        data: {
          isVerified: 1,
          verificationToken: null,
          verificationTokenExpiresAt: null,
        },
      });
      Logger.info(`[TEST_MODE] Auto-verified magic-link user`);
      return {
        message: 'Registration successful. Your account has been automatically verified.',
      };
    }

    Logger.info(`Magic-link registration initiated`);
    return {
      message: 'Registration successful. Please check your email to verify your account.',
    };
  } catch (err) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === 'P2002') {
      throw new Error('An account with this email already exists');
    }
    throw err;
  }
};
