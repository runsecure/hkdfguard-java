package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import java.util.Locale;

/** The process's CPU architecture, as the native loaders need to know it. */
enum CpuArchitecture {
    X64,
    X86,
    ARM64,
    ARM,
    OTHER;

    /** This JVM's architecture - X64 under Rosetta, even on Apple silicon. */
    static CpuArchitecture current() {
        return switch (System.getProperty("os.arch", "").toLowerCase(Locale.ROOT)) {
            case "amd64", "x86_64" -> X64;
            case "x86", "i386", "i486", "i586", "i686" -> X86;
            case "aarch64", "arm64" -> ARM64;
            case "arm", "arm32" -> ARM;
            default -> OTHER;
        };
    }
}
