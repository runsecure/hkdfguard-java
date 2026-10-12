/**
 * The interfaces every HkdfGuard component is written against, the rules every language port
 * shares (service names, configuration purposes, cache AADs), and the protected-cache base class.
 */
module io.github.runsecure.hkdfguard.abstractions {
    requires transitive io.github.runsecure.hkdfguard.diagnostics;

    exports io.github.runsecure.hkdfguard.abstractions;
}
