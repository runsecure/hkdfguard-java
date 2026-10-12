package io.github.runsecure.hkdfguard.keywrapping.v1;

import io.github.runsecure.hkdfguard.keywrapping.v1.interop.AbstractHkdfGuardKmsLibrary;
import io.github.runsecure.hkdfguard.keywrapping.v1.interop.LinuxHkdfGuardKmsLibrary;
import io.github.runsecure.hkdfguard.keywrapping.v1.interop.MacOsHkdfGuardKmsLibrary;
import io.github.runsecure.hkdfguard.keywrapping.v1.interop.WindowsHkdfGuardKmsLibrary;

/**
 * Resolves the current OS's native HkdfGuard KMS binding exactly once per process (binding the
 * wrong platform's library would fail on first native call anyway, so there's nothing to gain by
 * re-resolving per instance). Resolving binds nothing yet: each binding loads and verifies its
 * native library on its first call.
 */
final class NativeHost {
    private static AbstractHkdfGuardKmsLibrary library;

    private NativeHost() {
    }

    /**
     * This platform's binding.
     *
     * @throws UnsupportedOperationException there is no native KMS library for this platform
     */
    static synchronized AbstractHkdfGuardKmsLibrary library() {
        if (library == null)
            library = resolve(OsPlatform.current(), System.getProperty("os.name") + " " + System.getProperty("os.version"));
        return library;
    }

    /**
     * @param platform      the platform, or null when it is not one a native library exists for
     * @param osDescription named in the exception for an unsupported platform
     * @throws UnsupportedOperationException platform is null
     */
    static AbstractHkdfGuardKmsLibrary resolve(OsPlatform platform, String osDescription) {
        if (platform == null)
            throw new UnsupportedOperationException("HkdfGuard KeyWrapping V1 has no native KMS library for '" + osDescription + "'.");

        return switch (platform) {
            case WINDOWS -> new WindowsHkdfGuardKmsLibrary();
            case LINUX -> new LinuxHkdfGuardKmsLibrary();
            case MAC_OS -> new MacOsHkdfGuardKmsLibrary();
        };
    }
}
