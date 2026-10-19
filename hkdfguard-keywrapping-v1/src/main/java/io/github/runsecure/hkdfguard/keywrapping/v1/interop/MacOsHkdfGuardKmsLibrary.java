package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

/**
 * Binds libhkdfguard_v1.dylib (see the hkdfguard.h installed beside it), which holds the
 * per-service KEK as a Secure Enclave key. Each distinct service string gets its own, independent
 * Secure Enclave key - wrapping under one service's identifier and unwrapping under a different
 * one fails by design ({@link #ERR_KEK_FINGERPRINT_MISMATCH}). The library is installed separately -
 * system-wide at /Library/Application Support/HkdfGuard/v1, or per user at ~/.hkdfguard/v1 - and
 * loaded only from there, after the checks in {@link MacOsNativeLibraryLoader}.
 * <p>
 * No call here creates a KEK: a service must be provisioned first with
 * {@code hkdfguard-v1-initialize provision --service-name <name>}, or every wrap/unwrap fails with
 * {@link #ERR_KEK_NOT_FOUND}. Status codes are the shared table in
 * {@link AbstractHkdfGuardKmsLibrary}.
 */
public final class MacOsHkdfGuardKmsLibrary extends NativeKmsLibrary {
    @Override
    public String describeStatus(int status) {
        return switch (status) {
            case ERR_PROVIDER_UNAVAILABLE -> "this Mac has no Secure Enclave";
            case ERR_PAYLOAD_AUTH_FAILED -> "AES-GCM authentication failed: the payload was altered, or wrapped for another service under this KEK";
            case ERR_KEK_NOT_FOUND -> "no KEK is provisioned for this service in this keychain mode; run hkdfguard-v1-initialize provision";
            case ERR_KEK_ACCESS_DENIED -> "the keychain denied access: it is locked, there is no session to prompt in, or this process isn't allowed";
            case ERR_KEK_INVALID -> "the keychain item for this service can't be reconstructed into a key";
            case ERR_PROCESS_HARDENING_FAILED -> "process hardening failed: core dumps or debugger attachment could not be denied, or (with REQUIRE_PROTECTED_SIGNATURE) the host executable's code signature still allows it - it needs the Hardened Runtime, without get-task-allow or DYLD_* entitlements";
            default -> super.describeStatus(status);
        };
    }

    @Override
    protected KmsFunctions bind() {
        var handle = MacOsNativeLibraryLoader.load();
        return KmsFunctions.bind(name -> MacOsNativeLibraryLoader.export(handle, name));
    }
}
