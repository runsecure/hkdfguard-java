package io.github.runsecure.hkdfguard.keywrapping.v1;

import java.util.Locale;

/** The operating systems a native KMS library exists for. */
enum OsPlatform {
    WINDOWS,
    LINUX,
    MAC_OS;

    /** This process's platform, or null if it is none of these. */
    static OsPlatform current() {
        var name = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (name.startsWith("windows"))
            return WINDOWS;
        if (name.startsWith("linux"))
            return LINUX;
        if (name.startsWith("mac os x") || name.startsWith("macos") || name.startsWith("darwin"))
            return MAC_OS;
        return null;
    }
}
