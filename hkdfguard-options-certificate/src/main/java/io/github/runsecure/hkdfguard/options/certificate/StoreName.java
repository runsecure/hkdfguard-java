package io.github.runsecure.hkdfguard.options.certificate;

/**
 * Which certificate store to open: .NET's X509 {@code StoreName}, every one of its names, so the
 * same configuration binds in either port. The JDK opens only {@link #MY} and {@link #ROOT} (its
 * SunMSCAPI KeyStores are Windows-MY-* and Windows-ROOT-*), so
 * {@link CertificateOptionsValidator} refuses the others.
 */
public enum StoreName {
    /** Other people's certificates (AddressBook). Not available on Java. */
    ADDRESS_BOOK,

    /** Third-party certification authorities (AuthRoot). Not available on Java. */
    AUTH_ROOT,

    /** Intermediate certification authorities (CA). Not available on Java. */
    CERTIFICATE_AUTHORITY,

    /** Revoked certificates (Disallowed). Not available on Java. */
    DISALLOWED,

    /** Personal certificates, with their private keys (My). */
    MY,

    /** Trusted root certification authorities (Root). */
    ROOT,

    /** Directly trusted people and resources (TrustedPeople). Not available on Java. */
    TRUSTED_PEOPLE,

    /** Directly trusted publishers (TrustedPublisher). Not available on Java. */
    TRUSTED_PUBLISHER,
}
