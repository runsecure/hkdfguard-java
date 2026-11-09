/**
 * Where one certificate and its private key are opened from, as plain data:
 * {@link io.github.runsecure.hkdfguard.options.certificate.CertificateOptions} is read from
 * configuration, checked by
 * {@link io.github.runsecure.hkdfguard.options.certificate.CertificateOptionsValidator}, and opened by
 * {@link io.github.runsecure.hkdfguard.options.certificate.CertificateOptionsLoader} into a
 * {@link io.github.runsecure.hkdfguard.options.certificate.LoadedCertificate}.
 */
module io.github.runsecure.hkdfguard.options.certificate {
    requires transitive io.github.runsecure.hkdfguard.abstractions;

    exports io.github.runsecure.hkdfguard.options.certificate;
}
