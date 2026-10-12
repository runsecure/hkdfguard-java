package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

/**
 * Binds HkdfGuardV1.dll, loaded only from %ProgramFiles%\HkdfGuard\v1 after the checks in
 * {@link WindowsNativeLibraryLoader}. It holds the per-service KEK as a persistent,
 * machine-wide-scoped, non-exportable P-256 key in the Microsoft Platform Crypto Provider
 * (TPM/vTPM) when available, or the Microsoft Software Key Storage Provider otherwise.
 * <p>
 * No call here creates a KEK: an elevated {@code hkdfguard-v1-initialize provision} must create it
 * first. A service name is 1-128 ASCII letters, digits or '.'.
 */
public final class WindowsHkdfGuardKmsLibrary extends NativeKmsLibrary {
    // Status codes, exactly as HkdfGuardV1's header defines them (HKDFGUARD_ERR_*).
    public static final int ERR_INVALID_ARG = -1;
    public static final int ERR_BUFFER_TOO_SMALL = -2;
    public static final int ERR_PROVIDER = -3;
    public static final int ERR_CRYPTO = -4;
    public static final int ERR_AUTH_FAILED = -5;
    public static final int ERR_MALFORMED = -6;
    public static final int ERR_INTERNAL = -7;
    public static final int ERR_SERVICE_NAME_INVALID = -8;
    public static final int ERR_INVALID_POLICY = -9;
    public static final int ERR_GROUP_INVALID = -10;
    public static final int ERR_KEK_MISMATCH = -11;
    public static final int ERR_KEK_NOT_FOUND = -12;
    public static final int ERR_ACCESS_DENIED = -13;
    public static final int ERR_KEK_ACL_INVALID = -14;

    @Override
    public String describeStatus(int status) {
        return switch (status) {
            case ERR_INVALID_ARG -> "invalid argument: a null pointer, wrong DEK length, or bad service";
            case ERR_BUFFER_TOO_SMALL -> "the output buffer is too small for the result";
            case ERR_PROVIDER -> "the KEK provider or key could not be opened or created";
            case ERR_CRYPTO -> "an ECDH, HKDF or AES operation failed";
            case ERR_AUTH_FAILED -> "AES-GCM authentication failed: the wrapped payload was altered";
            case ERR_MALFORMED -> "the wrapped payload is not a valid WrappedDekV1";
            case ERR_INTERNAL -> "an unexpected internal failure in the native library";
            case ERR_SERVICE_NAME_INVALID -> "the service name is malformed or invalid";
            case ERR_INVALID_POLICY -> "HKLM\\Software\\Policies\\HkdfGuard\\KeyStoragePolicy is invalid";
            case ERR_GROUP_INVALID -> "an HKLM\\Software\\Policies\\HkdfGuard\\KeyUseGroups entry is unresolvable, not a group, or over-broad";
            case ERR_KEK_MISMATCH -> "the payload was wrapped under a different KEK than this service's";
            case ERR_KEK_NOT_FOUND -> "no KEK is provisioned for this service; run hkdfguard-v1-initialize provision";
            case ERR_ACCESS_DENIED -> "the KEK exists, but this account is not authorized to use it; add it to the HkdfGuardUsers group or a KeyUseGroups group";
            case ERR_KEK_ACL_INVALID -> "the existing KEK's ACL is missing, lacks SYSTEM/Administrators, or grants an over-broad principal";
            default -> null;
        };
    }

    @Override
    protected KmsFunctions bind() {
        var handle = WindowsNativeLibraryLoader.load();
        return KmsFunctions.bind(name -> WindowsNativeLibraryLoader.export(handle, name));
    }
}
