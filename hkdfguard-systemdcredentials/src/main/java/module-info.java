/**
 * Linux credentials through systemd-creds:
 * {@link io.github.runsecure.hkdfguard.systemdcredentials.SystemdCredentials} encrypts and decrypts
 * them, bound to this machine's host key, TPM or both, and
 * {@link io.github.runsecure.hkdfguard.systemdcredentials.SystemdCredentialSource} is a protected
 * read-only cache over them and the credentials systemd decrypts for a service.
 */
module io.github.runsecure.hkdfguard.systemdcredentials {
    requires transitive io.github.runsecure.hkdfguard.abstractions;
    requires transitive io.github.runsecure.hkdfguard.cache;

    exports io.github.runsecure.hkdfguard.systemdcredentials;
}
