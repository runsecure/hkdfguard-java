package io.github.runsecure.hkdfguard.options.certificate;

/** The format of a certificate file. */
public enum CertificateFileFormat {
    /** A PKCS#12 (.pfx/.p12) file holding the certificate and its key. */
    PKCS12,

    /** A PEM certificate, with its key in {@link CertificateFileOptions#getKeyPath()} as encrypted PKCS#8. */
    PEM,
}
