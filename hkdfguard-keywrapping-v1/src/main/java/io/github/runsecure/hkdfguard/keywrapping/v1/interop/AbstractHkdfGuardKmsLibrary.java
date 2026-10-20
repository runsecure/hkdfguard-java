package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import io.github.runsecure.hkdfguard.abstractions.InvalidKeyFileException;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.NoSuchFileException;
import java.util.Arrays;
import java.util.Objects;

/**
 * Shared surface over a platform's native HkdfGuard KMS library. Every implementation wraps and
 * unwraps a fixed-length DEK under a persistent, per-service KEK held outside the JVM (a TPM2 key,
 * a Secure Enclave key, etc.) via that platform's hkdfguard_wrap_dek / hkdfguard_unwrap_dek /
 * hkdfguard_generate_and_wrap_dek native functions, and reads wrapped-key files through
 * hkdfguard_open_file. The functions are identical in shape across platforms, and so are their
 * status codes: the native header's HKDFGUARD_ERR_* table is shared number for number by the
 * Windows, Linux and macOS libraries, so it lives here, once.
 * <p>
 * Internal to the KeyWrapping module: this package is not exported.
 */
public abstract class AbstractHkdfGuardKmsLibrary {
    public static final int DEK_LENGTH = 32;

    // Status codes, exactly as every platform's hkdfguard.h defines them (HKDFGUARD_OK and
    // HKDFGUARD_ERR_*). Each platform band refines one of the common codes above it. Codes not
    // listed here (-7, -13..-15, -21..-31, -40..-63, ...) are reserved.

    /** The call succeeded. */
    public static final int OK = 0;

    // General (-1..-7)
    public static final int ERR_INVALID_ARGUMENT = -1;
    public static final int ERR_BUFFER_TOO_SMALL = -2;
    public static final int ERR_PROVIDER_UNAVAILABLE = -3;
    public static final int ERR_PROVIDER_ERROR = -4;
    public static final int ERR_CRYPTO_ERROR = -5;
    public static final int ERR_INTERNAL_ERROR = -6;

    // Service name and policy (-8..-9)
    public static final int ERR_INVALID_SERVICE_NAME = -8;
    public static final int ERR_POLICY_INVALID = -9;

    // Wrapped payload (-10..-15)
    public static final int ERR_PAYLOAD_MALFORMED = -10;
    public static final int ERR_PAYLOAD_AUTH_FAILED = -11;
    public static final int ERR_PAYLOAD_UNSUPPORTED = -12;

    // KEK and process (-16..-31)
    public static final int ERR_KEK_FINGERPRINT_MISMATCH = -16;
    public static final int ERR_KEK_NOT_FOUND = -17;
    public static final int ERR_KEK_ACCESS_DENIED = -18;
    public static final int ERR_KEK_INVALID = -19;
    public static final int ERR_PROCESS_HARDENING_FAILED = -20;

    // Key file, hkdfguard_open_file (-32..-39)
    public static final int ERR_FILE_NOT_FOUND = -32;
    public static final int ERR_FILE_ACCESS_DENIED = -33;
    public static final int ERR_FILE_IO = -34;
    public static final int ERR_FILE_TOO_SHORT = -35;
    public static final int ERR_FILE_TOO_LONG = -36;
    public static final int ERR_FILE_PLAINTEXT_KEY = -37;
    public static final int ERR_FILE_MALFORMED = -38;
    public static final int ERR_FILE_UNTRUSTED = -39;

    // Windows-specific (-64..-79), refining ERR_POLICY_INVALID
    public static final int ERR_WIN_GROUP_INVALID = -64;

    // macOS-specific (-96..-111), each refining ERR_PROVIDER_ERROR
    public static final int ERR_MAC_ACCESS_CONTROL_CREATION_FAILED = -96;
    public static final int ERR_MAC_KEY_GENERATION_FAILED = -97;
    public static final int ERR_MAC_KEYCHAIN_WRITE_FAILED = -98;
    public static final int ERR_MAC_KEK_VERIFICATION_FAILED = -99;
    public static final int ERR_MAC_KEYCHAIN_READ_FAILED = -100;

    /**
     * hkdfguard_harden_process_with_flags' HKDFGUARD_HARDEN_REQUIRE_PROTECTED_SIGNATURE: fail unless
     * no other process of the same user can debug or inject into this one. Same bit on every
     * platform.
     */
    public static final int HARDEN_REQUIRE_PROTECTED_SIGNATURE = 0x1;

    protected AbstractHkdfGuardKmsLibrary() {
    }

    /**
     * What a non-{@link #OK} status means, for error messages - or null when the code is unknown.
     * The meanings are shared by every platform; a platform's binding overrides this to add what to
     * do about a code there (which group grants access to a KEK, where the policy lives) and falls
     * back to this for the rest.
     */
    public String describeStatus(int status) {
        return switch (status) {
            case ERR_INVALID_ARGUMENT -> "invalid argument: a null pointer, wrong DEK length, negative buffer capacity, or bad path";
            case ERR_BUFFER_TOO_SMALL -> "the output buffer is too small for the result";
            case ERR_PROVIDER_UNAVAILABLE -> "no key storage provider could be used at all";
            case ERR_PROVIDER_ERROR -> "the KEK provider or key could not be opened or created";
            case ERR_CRYPTO_ERROR -> "an ECDH, HKDF, AES or random number operation failed";
            case ERR_INTERNAL_ERROR -> "an unexpected internal failure in the native library";
            case ERR_INVALID_SERVICE_NAME -> "the service name is null, empty, too long, or has a character other than an ASCII letter, digit or '.'";
            case ERR_POLICY_INVALID -> "the machine's HkdfGuard policy is invalid";
            case ERR_PAYLOAD_MALFORMED -> "the wrapped payload is not a valid WrappedDekV1";
            case ERR_PAYLOAD_AUTH_FAILED -> "AES-GCM authentication failed: the wrapped payload was altered";
            case ERR_PAYLOAD_UNSUPPORTED -> "the wrapped payload's version or suite is not one this native library understands";
            case ERR_KEK_FINGERPRINT_MISMATCH -> "the payload was wrapped under a different KEK than this service's current one";
            case ERR_KEK_NOT_FOUND -> "no KEK is provisioned for this service; run hkdfguard provision";
            case ERR_KEK_ACCESS_DENIED -> "the KEK exists, but this account is not authorized to use it";
            case ERR_KEK_INVALID -> "the existing KEK is unusable as found";
            case ERR_PROCESS_HARDENING_FAILED -> "process hardening failed";
            case ERR_FILE_NOT_FOUND -> "the key file, or a folder in its path, does not exist";
            case ERR_FILE_ACCESS_DENIED -> "this account may not read the key file";
            case ERR_FILE_IO -> "the key file is not a regular file, is in use by a writer, or could not be read";
            case ERR_FILE_TOO_SHORT -> "the key file is shorter than a wrapped DEK";
            case ERR_FILE_TOO_LONG -> "the key file is longer than a wrapped DEK";
            case ERR_FILE_PLAINTEXT_KEY -> "the key file holds what looks like an UNWRAPPED key (32 raw bytes, or its hex or base64): treat it as a key exposure";
            case ERR_FILE_MALFORMED -> "the key file is the right size, but is not a valid wrapped DEK";
            case ERR_FILE_UNTRUSTED -> "the key file's path is not trusted: a link or reparse point, a short or network path, or a file or folder another account could replace";
            case ERR_WIN_GROUP_INVALID -> "an HKLM\\Software\\Policies\\HkdfGuard\\KeyUseGroups entry is unresolvable, not a group, not host-local, or over-broad";
            case ERR_MAC_ACCESS_CONTROL_CREATION_FAILED -> "the access policy for a new KEK could not be created";
            case ERR_MAC_KEY_GENERATION_FAILED -> "the Secure Enclave refused to generate a key";
            case ERR_MAC_KEYCHAIN_WRITE_FAILED -> "the new KEK could not be stored in the keychain";
            case ERR_MAC_KEK_VERIFICATION_FAILED -> "the new KEK could not be reloaded after it was stored";
            case ERR_MAC_KEYCHAIN_READ_FAILED -> "the keychain could not be read";
            default -> null;
        };
    }

    /**
     * Wraps {@code dek} under the persistent KEK identified by {@code service}.
     *
     * @param service     non-empty, cross-platform identity of the KEK
     * @param dek         the plaintext DEK to wrap (must be exactly {@link #DEK_LENGTH} bytes)
     * @param destination receives the wrapped payload
     * @return {@link #OK} and the number of bytes written; or a negative status - with, on a
     *         buffer-too-small failure, the required capacity
     */
    public abstract KmsResult wrapDek(String service, byte[] dek, byte[] destination);

    /**
     * Unwraps a payload previously produced by {@link #wrapDek} for the same {@code service},
     * recovering the original DEK.
     *
     * @return {@link #OK} and {@link #DEK_LENGTH}; or a negative status
     */
    public abstract KmsResult unwrapDek(String service, byte[] wrapped, byte[] destination);

    /**
     * Generates a fresh, cryptographically random DEK and immediately wraps it under the persistent
     * KEK identified by {@code service}. The plaintext DEK never crosses this boundary - recover it
     * later via {@link #unwrapDek} with the same {@code service}.
     *
     * @return {@link #OK} and the number of bytes written; or a negative status
     */
    public abstract KmsResult generateAndWrapDek(String service, byte[] destination);

    /**
     * Makes this process's memory harder to recover, through hkdfguard_harden_process_with_flags -
     * on every platform: no crash dumps of its memory, and no debugger attach or memory reads by
     * other processes of the same user. What that takes differs per platform; see
     * NativeProcessHardening.
     *
     * @param flags a bitwise OR of the HKDFGUARD_HARDEN_* flags ({@link #HARDEN_REQUIRE_PROTECTED_SIGNATURE}), or 0
     * @return {@link #OK} on success, or a negative status: {@link #ERR_PROCESS_HARDENING_FAILED},
     *         or {@link #ERR_INVALID_ARGUMENT} for an unknown flag
     */
    public abstract int hardenProcess(int flags);

    /**
     * Reads a wrapped-key file through the native library's hkdfguard_open_file, which refuses a
     * file whose path, owner or permissions mean someone else could have replaced it, and one that
     * holds what looks like an unwrapped key - checks only the platform can make. The bytes come
     * back still wrapped, ready for {@link #unwrapDek}; no KEK is touched.
     *
     * @param path the key file's path, absolute or relative to the current directory
     * @return the file's wrapped payload: exactly this platform's wrapped DEK length
     * @throws NullPointerException     path is null
     * @throws IllegalArgumentException path is empty or holds a NUL character (checked before the
     *                                  native call), or the native library rejected it as invalid
     * @throws NoSuchFileException      the file, or a folder in its path, does not exist
     * @throws AccessDeniedException    this account may not read the file, or its path is not trusted
     * @throws InvalidKeyFileException  the file is the wrong size, holds what looks like an unwrapped
     *                                  key, or isn't a valid wrapped DEK
     * @throws IOException              the file could not be read for another reason
     */
    public final byte[] openFile(String path) throws IOException {
        Objects.requireNonNull(path, "path");
        if (path.isEmpty())
            throw new IllegalArgumentException("The key file path must not be empty.");
        // A C string ends at the first NUL: the native library would read a different path.
        if (path.indexOf('\0') >= 0)
            throw new IllegalArgumentException("The key file path must not contain a NUL character.");

        // Every platform's wrapped DEK fits in WrappedKeyLimits.MAX_BYTES (Windows 132, Linux 276,
        // macOS 125 bytes), so one buffer never needs the size probe.
        var buffer = new byte[WrappedKeyLimits.MAX_BYTES];
        var result = openFileRaw(path, buffer);
        var status = result.status();
        if (status == OK)
            return Arrays.copyOf(buffer, Math.clamp(result.bytesWritten(), 0, buffer.length));

        var description = describeStatus(status);
        var message = "Key file '" + path + "' was refused by the native library with status " + status
                + " (" + (description != null ? description : "unknown status") + ").";
        if (status == ERR_INVALID_ARGUMENT)
            throw new IllegalArgumentException(message);

        // NoSuchFileException and AccessDeniedException carry the path as getFile(), and the
        // message as getReason().
        throw switch (status) {
            case ERR_FILE_NOT_FOUND -> new NoSuchFileException(path, null, message);
            case ERR_FILE_ACCESS_DENIED, ERR_FILE_UNTRUSTED -> new AccessDeniedException(path, null, message);
            case ERR_FILE_TOO_SHORT, ERR_FILE_TOO_LONG, ERR_FILE_PLAINTEXT_KEY, ERR_FILE_MALFORMED -> new InvalidKeyFileException(message);
            default -> new IOException(message);
        };
    }

    /**
     * The raw hkdfguard_open_file call: reads {@code path} into {@code destination} without
     * unwrapping it.
     *
     * @param path        a non-empty path without NUL characters, passed as UTF-8
     * @param destination receives the file's bytes; its length is the capacity passed
     * @return {@link #OK} and the number of bytes read; or a negative status
     */
    protected abstract KmsResult openFileRaw(String path, byte[] destination);
}
