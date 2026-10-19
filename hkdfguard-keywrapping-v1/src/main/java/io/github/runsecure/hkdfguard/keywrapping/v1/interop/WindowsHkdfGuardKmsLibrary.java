package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

/**
 * Binds HkdfGuard.dll, loaded only from %ProgramFiles%\HkdfGuard\v1 after the checks in
 * {@link WindowsNativeLibraryLoader}. It holds the per-service KEK as a persistent,
 * machine-wide-scoped, non-exportable P-256 key in the Microsoft Platform Crypto Provider
 * (TPM/vTPM) when available, or the Microsoft Software Key Storage Provider otherwise.
 * <p>
 * No call here creates a KEK: an elevated {@code hkdfguard provision} must create it first. A
 * service name is 1-128 ASCII letters, digits or '.'. Status codes are the shared table in
 * {@link AbstractHkdfGuardKmsLibrary}.
 */
public final class WindowsHkdfGuardKmsLibrary extends NativeKmsLibrary {
    @Override
    public String describeStatus(int status) {
        return switch (status) {
            case ERR_PROVIDER_ERROR -> "the KEK's key storage provider (Platform Crypto Provider or Software KSP) could not open or create the key";
            case ERR_POLICY_INVALID -> "a machine policy value under HKLM\\Software\\Policies\\HkdfGuard is invalid";
            case ERR_KEK_NOT_FOUND -> "no KEK is provisioned for this service; run hkdfguard provision from an elevated prompt";
            case ERR_KEK_ACCESS_DENIED -> "the KEK exists, but this account is not authorized to use it (or, for a new KEK, the process is not elevated); add it to the HkdfGuardUsers group or a KeyUseGroups group";
            case ERR_KEK_INVALID -> "the existing KEK's ACL is missing, lacks SYSTEM/Administrators, or grants an over-broad principal";
            case ERR_PROCESS_HARDENING_FAILED -> "process hardening failed: the crash-report heap exclusion or the process and thread access lists could not be set, or (with REQUIRE_PROTECTED_SIGNATURE) the process could not be closed to its own user";
            default -> super.describeStatus(status);
        };
    }

    @Override
    protected KmsFunctions bind() {
        var handle = WindowsNativeLibraryLoader.load();
        return KmsFunctions.bind(name -> WindowsNativeLibraryLoader.export(handle, name));
    }
}
