/**
 * Encrypted session cookie payload, sign/verify via jose's JWE (A256GCM).
 * Unlike the main app's account-sessions.ts (which stores signed-but-
 * unencrypted refresh JWTs directly), this encrypts the whole session
 * blob at rest — required by the SDK's "Encrypted httpOnly cookie
 * sessions" spec. Web Crypto + jose only, no Node built-ins, so this
 * works unmodified in Node, browsers, and edge runtimes.
 */
import { CompactEncrypt, compactDecrypt } from "jose";
import { AccountsError } from "../core/errors.js";

export interface SessionCookiePayload {
    accessToken: string;
    refreshToken?: string;
    idToken?: string;
    /** Epoch milliseconds. */
    expiresAt: number;
}

const ALG = "dir";
const ENC = "A256GCM";

/**
 * Derives a 256-bit symmetric key from an arbitrary-length secret string
 * (e.g. an env var) via SHA-256. Callers should pass a high-entropy
 * secret (32+ random bytes, base64 or hex encoded) — this does not add
 * entropy, it only shapes the input into the fixed-length key A256GCM
 * requires.
 */
export async function deriveSessionKey(
    secretString: string,
): Promise<Uint8Array> {
    if (!secretString || secretString.length < 32) {
        throw new AccountsError(
            "configuration_error",
            "deriveSessionKey: secretString must be at least 32 characters of high-entropy input",
        );
    }
    const encoder = new TextEncoder();
    const digest = await crypto.subtle.digest(
        "SHA-256",
        encoder.encode(secretString),
    );
    return new Uint8Array(digest);
}

/**
 * Encrypts a session payload into a compact JWE string, suitable for
 * storing directly as an httpOnly cookie value.
 */
export async function encryptSession(
    payload: SessionCookiePayload,
    key: Uint8Array,
): Promise<string> {
    const plaintext = new TextEncoder().encode(JSON.stringify(payload));
    return new CompactEncrypt(plaintext)
        .setProtectedHeader({ alg: ALG, enc: ENC })
        .encrypt(key);
}

/**
 * Decrypts a session cookie value. Returns null on any failure — expired
 * key rotation, tampering, malformed input, wrong key — matching the
 * codebase's existing verifyJWT() convention of "null means not
 * authenticated," never throwing for the expected-failure case. Only
 * genuine misconfiguration (e.g. missing key) should throw, and that
 * happens upstream in deriveSessionKey.
 */
export async function decryptSession(
    cookieValue: string,
    key: Uint8Array,
): Promise<SessionCookiePayload | null> {
    try {
        const { plaintext } = await compactDecrypt(cookieValue, key);
        const parsed: unknown = JSON.parse(new TextDecoder().decode(plaintext));
        if (!isSessionCookiePayload(parsed)) return null;
        return parsed;
    } catch {
        return null;
    }
}

function isSessionCookiePayload(value: unknown): value is SessionCookiePayload {
    if (typeof value !== "object" || value === null) return false;
    const record = value as Record<string, unknown>;
    return (
        typeof record.accessToken === "string" &&
        typeof record.expiresAt === "number" &&
        (record.refreshToken === undefined ||
            typeof record.refreshToken === "string") &&
        (record.idToken === undefined || typeof record.idToken === "string")
    );
}
