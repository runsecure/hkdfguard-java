package io.github.runsecure.hkdfguard.securefile;

/** The kinds of file {@link UnixKeyFileChecks} tells apart. */
enum UnixFileType {
    OTHER,
    REGULAR_FILE,
    DIRECTORY,
    SYMBOLIC_LINK,
}
