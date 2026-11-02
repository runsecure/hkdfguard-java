package io.github.runsecure.hkdfguard.cache;

/** How a {@link RemoteSecretCache} matches names, which must be how its secret store does. */
public enum SecretNameMatching {
    /** Names differing only in ASCII case are one secret (e.g. Azure Key Vault). */
    IGNORE_ASCII_CASE,

    /**
     * Names are matched exactly; names differing in case are different secrets (e.g. AWS Secrets
     * Manager, Google Secret Manager). A name holding '!' is reported missing without a fetch -
     * none of those stores allow it, and it marks case in entry names (see
     * {@link RemoteSecretCache}).
     */
    EXACT,
}
