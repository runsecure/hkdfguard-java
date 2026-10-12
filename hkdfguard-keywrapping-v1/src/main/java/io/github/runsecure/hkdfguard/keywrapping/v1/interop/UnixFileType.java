package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

/** The kinds of file the macOS loader tells apart. */
enum UnixFileType {
    OTHER,
    REGULAR_FILE,
    DIRECTORY,
    SYMBOLIC_LINK,
}
