package io.github.runsecure.hkdfguard.options.certificate;

import java.util.Locale;

/** The operating systems a native certificate source is for, and how each is described in a failure. */
enum Platform {
    WINDOWS("Windows"),
    MACOS("macOS"),
    LINUX("Linux"),
    OTHER("another operating system");

    private final String description;

    Platform(String description) {
        this.description = description;
    }

    String description() {
        return description;
    }

    /** The platform this process runs on. */
    static Platform current() {
        var name = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        return of(name.startsWith("windows"), name.startsWith("mac"), name.startsWith("linux"));
    }

    /** The platform an OS is, from its checks, the first that holds; anything else is OTHER, which no native source is for. */
    static Platform of(boolean isWindows, boolean isMacOS, boolean isLinux) {
        return isWindows ? WINDOWS : isMacOS ? MACOS : isLinux ? LINUX : OTHER;
    }
}
