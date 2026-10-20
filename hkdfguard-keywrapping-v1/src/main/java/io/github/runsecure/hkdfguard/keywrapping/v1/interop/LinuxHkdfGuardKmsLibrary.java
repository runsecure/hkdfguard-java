package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

/**
 * Binds libhkdfguard.so.1 from the libhkdfguard1 package (hkdfguard-libs on RPM distributions; see
 * hkdfguard.h), loaded only from its install location - /usr/lib/&lt;multiarch&gt; or /usr/lib64 -
 * after the checks in {@link LinuxNativeLibraryLoader}, never by name through the dynamic linker's
 * search. It holds the per-service KEK on the strongest provider the root-owned policy allows -
 * TPM2, PKCS#11 or an external secret file. Every native call returns a plain status code, from the
 * shared table in {@link AbstractHkdfGuardKmsLibrary}.
 * <p>
 * No call here creates a KEK: {@code hkdfguard provision --service-name <name>} (/usr/bin/hkdfguard)
 * must create it first, or wrap fails with {@link #ERR_KEK_NOT_FOUND}.
 */
public final class LinuxHkdfGuardKmsLibrary extends NativeKmsLibrary {
    @Override
    public String describeStatus(int status) {
        return switch (status) {
            case ERR_PROVIDER_UNAVAILABLE -> "no KEK provider could be reached: no usable TPM, PKCS#11 token or external secret under /etc/hkdfguard/policy.toml";
            case ERR_PROVIDER_ERROR -> "a KEK provider was reached but failed (policy file, secret file permissions, TPM or token error); the native library's log names the reason";
            case ERR_POLICY_INVALID -> "/etc/hkdfguard/policy.toml can't be used: unparsable, an invalid or contradictory setting, insecure ownership or permissions, or a provider this build lacks";
            case ERR_KEK_NOT_FOUND -> "no KEK is provisioned for this service; run hkdfguard provision";
            case ERR_KEK_FINGERPRINT_MISMATCH -> "the payload was wrapped under a different KEK than this service's current one: another service, or the KEK or TPM derivation secret has changed";
            case ERR_PROCESS_HARDENING_FAILED -> "process hardening failed: core dumps or ptrace access could not be disabled";
            default -> super.describeStatus(status);
        };
    }

    @Override
    protected KmsFunctions bind() {
        var library = LinuxNativeLibraryLoader.load();
        return KmsFunctions.bind(name -> LinuxNativeLibraryLoader.export(library, name));
    }
}
