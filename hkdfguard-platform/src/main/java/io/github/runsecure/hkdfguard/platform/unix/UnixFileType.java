package io.github.runsecure.hkdfguard.platform.unix;

/** The kinds of file the Linux and macOS path checks tell apart. */
public enum UnixFileType {
    OTHER,
    REGULAR_FILE,
    DIRECTORY,
    SYMBOLIC_LINK,
}
