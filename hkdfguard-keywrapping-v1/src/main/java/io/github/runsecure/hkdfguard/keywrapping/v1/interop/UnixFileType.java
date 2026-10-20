package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

/** The kinds of file the macOS and Linux loaders tell apart. */
enum UnixFileType {
    OTHER,
    REGULAR_FILE,
    DIRECTORY,
    SYMBOLIC_LINK,
}
