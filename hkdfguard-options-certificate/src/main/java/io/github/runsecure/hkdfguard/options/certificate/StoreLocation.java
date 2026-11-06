package io.github.runsecure.hkdfguard.options.certificate;

/**
 * Which certificate store location to open: .NET's X509 {@code StoreLocation}, under the same
 * names (configuration's {@code "CurrentUser"} and {@code "LocalMachine"} read as these).
 */
public enum StoreLocation {
    /** The store of the account the process runs as: Windows' CurrentUser stores, the user's keychains on macOS. */
    CURRENT_USER,

    /** The machine's store, which only administrators can write: Windows' LocalMachine stores, the system keychains on macOS. */
    LOCAL_MACHINE,
}
