package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

/**
 * Binds libhkdfguard_v1.dylib (see the hkdfguard.h installed beside it), which holds the
 * per-service KEK as a Secure Enclave key. Each distinct service string gets its own, independent
 * Secure Enclave key - wrapping under one service's identifier and unwrapping under a different
 * one fails by design ({@link #ERR_FINGERPRINT_MISMATCH}). The library is installed separately -
 * system-wide at /Library/Application Support/HkdfGuard/v1, or per user at ~/.hkdfguard/v1 - and
 * loaded only from there, after the checks in {@link MacOsNativeLibraryLoader}.
 * <p>
 * No call here creates a KEK: a service must be provisioned first with
 * {@code hkdfguard-v1-initialize provision --service-name <name>}, or every wrap/unwrap fails with
 * {@link #ERR_KEK_NOT_FOUND}.
 */
public final class MacOsHkdfGuardKmsLibrary extends NativeKmsLibrary {
    // Status codes, exactly as hkdfguard.h documents them.
    public static final int ERR_INVALID_INPUT_LENGTH = -1;
    public static final int ERR_OUTPUT_BUFFER_TOO_SMALL = -2;
    public static final int ERR_KEY_UNAVAILABLE = -3;          // reserved; no longer returned
    public static final int ERR_PUBLIC_KEY_UNAVAILABLE = -4;   // reserved; never returned
    public static final int ERR_ENCRYPTION_FAILED = -5;
    public static final int ERR_DECRYPTION_FAILED = -6;
    public static final int ERR_UNEXPECTED_OUTPUT_LENGTH = -7;
    public static final int ERR_INVALID_SERVICE_IDENTIFIER = -8;
    public static final int ERR_ENCLAVE_UNAVAILABLE = -9;
    public static final int ERR_KEK_NOT_FOUND = -10;
    public static final int ERR_KEK_CORRUPTED = -11;
    public static final int ERR_ACCESS_CONTROL_CREATION_FAILED = -12;
    public static final int ERR_KEY_GENERATION_FAILED = -13;
    public static final int ERR_KEYCHAIN_WRITE_FAILED = -14;
    public static final int ERR_KEK_VERIFICATION_FAILED = -15;
    public static final int ERR_FINGERPRINT_MISMATCH = -16;
    public static final int ERR_KEYCHAIN_ACCESS_DENIED = -17;
    public static final int ERR_KEYCHAIN_READ_FAILED = -18;

    @Override
    public String describeStatus(int status) {
        return switch (status) {
            case ERR_INVALID_INPUT_LENGTH -> "invalid input length, or a null buffer";
            case ERR_OUTPUT_BUFFER_TOO_SMALL -> "the output buffer is too small for the result";
            case ERR_ENCRYPTION_FAILED -> "encryption failed";
            case ERR_DECRYPTION_FAILED -> "AES-GCM authentication failed: the payload was altered, or wrapped for another service under this KEK";
            case ERR_UNEXPECTED_OUTPUT_LENGTH -> "the native library produced an unexpected output length";
            case ERR_INVALID_SERVICE_IDENTIFIER -> "the service name is null, empty, too long, or has a character other than an ASCII letter, digit or '.'";
            case ERR_ENCLAVE_UNAVAILABLE -> "this Mac has no Secure Enclave";
            case ERR_KEK_NOT_FOUND -> "no KEK is provisioned for this service in this keychain mode; run hkdfguard-v1-initialize provision";
            case ERR_KEK_CORRUPTED -> "the keychain item for this service can't be reconstructed into a key";
            case ERR_ACCESS_CONTROL_CREATION_FAILED -> "the access policy for a new KEK could not be created";
            case ERR_KEY_GENERATION_FAILED -> "the Secure Enclave refused to generate a key";
            case ERR_KEYCHAIN_WRITE_FAILED -> "the new KEK could not be stored in the keychain";
            case ERR_KEK_VERIFICATION_FAILED -> "the new KEK could not be reloaded after it was stored";
            case ERR_FINGERPRINT_MISMATCH -> "the payload was wrapped under a different KEK than this service's";
            case ERR_KEYCHAIN_ACCESS_DENIED -> "the keychain denied access: it is locked, there is no session to prompt in, or this process isn't allowed";
            case ERR_KEYCHAIN_READ_FAILED -> "the keychain could not be read";
            default -> null; // includes -3 and -4, which the header reserves and never returns
        };
    }

    @Override
    protected KmsFunctions bind() {
        var handle = MacOsNativeLibraryLoader.load();
        return KmsFunctions.bind(name -> MacOsNativeLibraryLoader.export(handle, name));
    }
}
