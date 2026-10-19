package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import io.github.runsecure.hkdfguard.keywrapping.v1.NativeLibraryNotFoundException;
import java.lang.foreign.Arena;
import java.lang.foreign.SymbolLookup;

/**
 * Binds libHkdfGuardKeyProtectionLinux.so (see hkdfguard.h), which picks the strongest available
 * provider on the host - TPM2 &gt; PKCS#11 &gt; external secret &gt; software &gt; ephemeral - to hold
 * the per-service KEK. Every native call returns a plain status code, from the shared table in
 * {@link AbstractHkdfGuardKmsLibrary}. Loaded by the dynamic linker's default search, as the .NET
 * library does.
 * <p>
 * No call here creates a KEK: {@code hkdfguard provision --service-name <name>} (/usr/bin/hkdfguard)
 * must create it first, or wrap fails with {@link #ERR_KEK_NOT_FOUND}.
 */
@SuppressWarnings("restricted") // Loads the library through the FFM API; the module requires --enable-native-access.
public final class LinuxHkdfGuardKmsLibrary extends NativeKmsLibrary {
    static final String LIBRARY_NAME = "HkdfGuardKeyProtectionLinux";

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
        var fileName = System.mapLibraryName(LIBRARY_NAME);
        SymbolLookup library;
        try {
            library = SymbolLookup.libraryLookup(fileName, Arena.global());
        } catch (IllegalArgumentException e) {
            throw new NativeLibraryNotFoundException("The HkdfGuard native KMS library '" + fileName + "' could not be loaded.", e);
        }

        return KmsFunctions.bind(name -> library.find(name)
                .orElseThrow(() -> new IllegalStateException("'" + fileName + "' has no '" + name + "' export.")));
    }
}
