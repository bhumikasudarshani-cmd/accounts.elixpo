import { describe, expect, it } from "vitest";
import type { AccountsError } from "../core/errors.js";
import {
    decryptSession,
    deriveSessionKey,
    encryptSession,
    type SessionCookiePayload,
} from "../server/session.js";

const VALID_SECRET = "a".repeat(32); // meets the 32-char minimum
const OTHER_SECRET = "b".repeat(32);

const SAMPLE_PAYLOAD: SessionCookiePayload = {
    accessToken: "access-token-value",
    refreshToken: "refresh-token-value",
    idToken: "id-token-value",
    expiresAt: Date.now() + 900_000,
};

describe("deriveSessionKey", () => {
    it("derives a 32-byte key from a valid secret", async () => {
        const key = await deriveSessionKey(VALID_SECRET);
        expect(key).toBeInstanceOf(Uint8Array);
        expect(key.length).toBe(32); // SHA-256 output
    });

    it("derives the same key for the same secret (deterministic)", async () => {
        const keyA = await deriveSessionKey(VALID_SECRET);
        const keyB = await deriveSessionKey(VALID_SECRET);
        expect(Array.from(keyA)).toEqual(Array.from(keyB));
    });

    it("derives different keys for different secrets", async () => {
        const keyA = await deriveSessionKey(VALID_SECRET);
        const keyB = await deriveSessionKey(OTHER_SECRET);
        expect(Array.from(keyA)).not.toEqual(Array.from(keyB));
    });

    it("throws AccountsError for a secret shorter than 32 characters", async () => {
        await expect(deriveSessionKey("too-short")).rejects.toMatchObject({
            code: "configuration_error",
        });
    });

    it("throws AccountsError for an empty secret", async () => {
        await expect(deriveSessionKey("")).rejects.toMatchObject({
            code: "configuration_error",
        });
    });

    it("does not include the secret value in the thrown error message", async () => {
        const secret = "short-secret-value";
        try {
            await deriveSessionKey(secret);
            throw new Error("expected deriveSessionKey to throw");
        } catch (err) {
            const message = (err as AccountsError).message;
            expect(message).not.toContain(secret);
        }
    });
});

describe("encryptSession / decryptSession", () => {
    it("round-trips a session payload through encrypt then decrypt", async () => {
        const key = await deriveSessionKey(VALID_SECRET);
        const cookieValue = await encryptSession(SAMPLE_PAYLOAD, key);
        const decrypted = await decryptSession(cookieValue, key);
        expect(decrypted).toEqual(SAMPLE_PAYLOAD);
    });

    it("round-trips a payload without optional fields", async () => {
        const key = await deriveSessionKey(VALID_SECRET);
        const minimalPayload: SessionCookiePayload = {
            accessToken: "access-only",
            expiresAt: Date.now() + 60_000,
        };
        const cookieValue = await encryptSession(minimalPayload, key);
        const decrypted = await decryptSession(cookieValue, key);
        expect(decrypted).toEqual(minimalPayload);
    });

    it("produces a different ciphertext on each call (random IV)", async () => {
        const key = await deriveSessionKey(VALID_SECRET);
        const cookieA = await encryptSession(SAMPLE_PAYLOAD, key);
        const cookieB = await encryptSession(SAMPLE_PAYLOAD, key);
        expect(cookieA).not.toBe(cookieB);
    });

    it("returns null when decrypting with the wrong key", async () => {
        const encryptKey = await deriveSessionKey(VALID_SECRET);
        const wrongKey = await deriveSessionKey(OTHER_SECRET);
        const cookieValue = await encryptSession(SAMPLE_PAYLOAD, encryptKey);
        const decrypted = await decryptSession(cookieValue, wrongKey);
        expect(decrypted).toBeNull();
    });

    it("returns null for a tampered ciphertext", async () => {
        const key = await deriveSessionKey(VALID_SECRET);
        const cookieValue = await encryptSession(SAMPLE_PAYLOAD, key);
        // Flip a character in the middle of the compact JWE (header.iv.ciphertext.tag format)
        const parts = cookieValue.split(".");
        const middleIndex = Math.floor(parts.length / 2);
        const tamperedPart =
            parts[middleIndex].slice(0, -1) +
            (parts[middleIndex].endsWith("A") ? "B" : "A");
        parts[middleIndex] = tamperedPart;
        const tampered = parts.join(".");

        const decrypted = await decryptSession(tampered, key);
        expect(decrypted).toBeNull();
    });

    it("returns null for a malformed cookie value", async () => {
        const key = await deriveSessionKey(VALID_SECRET);
        const decrypted = await decryptSession("not-a-valid-jwe-at-all", key);
        expect(decrypted).toBeNull();
    });

    it("returns null for an empty cookie value", async () => {
        const key = await deriveSessionKey(VALID_SECRET);
        const decrypted = await decryptSession("", key);
        expect(decrypted).toBeNull();
    });

    it("returns null if the decrypted plaintext isn't a valid SessionCookiePayload shape", async () => {
        const key = await deriveSessionKey(VALID_SECRET);
        // Encrypt something that isn't a valid SessionCookiePayload by bypassing
        // the typed encryptSession() signature — simulate a corrupted/foreign payload.
        const { CompactEncrypt } = await import("jose");
        const plaintext = new TextEncoder().encode(
            JSON.stringify({ foo: "bar" }),
        );
        const cookieValue = await new CompactEncrypt(plaintext)
            .setProtectedHeader({ alg: "dir", enc: "A256GCM" })
            .encrypt(key);

        const decrypted = await decryptSession(cookieValue, key);
        expect(decrypted).toBeNull();
    });

    it("does not leak plaintext token values if decryption fails", async () => {
        const key = await deriveSessionKey(VALID_SECRET);
        const wrongKey = await deriveSessionKey(OTHER_SECRET);
        const cookieValue = await encryptSession(SAMPLE_PAYLOAD, key);

        const decrypted = await decryptSession(cookieValue, wrongKey);
        expect(decrypted).toBeNull();
        // Nothing to assert on message content since decryptSession returns null
        // rather than throwing — this test documents that contract explicitly.
    });
});
