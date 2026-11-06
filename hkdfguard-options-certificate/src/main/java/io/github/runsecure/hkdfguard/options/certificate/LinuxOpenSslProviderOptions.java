package io.github.runsecure.hkdfguard.options.certificate;

/**
 * A certificate on Linux whose private key is opened through an OpenSSL 3 provider - tpm2 for a key
 * in the TPM, or pkcs11 for a hardware token - beside the certificate itself as a PEM file, which
 * holds nothing secret.
 *
 * <p>Kept for configuration parity with .NET, where the key never leaves the provider. The JDK has
 * no counterpart to OpenSSL providers - SunPKCS11 is configured with a PKCS#11 library and slot, not
 * opened by a provider name and key URI - so on Java only the certificate itself can be loaded from
 * this source ({@link CertificateOptions#setRequirePrivateKey(boolean) requirePrivateKey} false);
 * {@link CertificateOptionsValidator} refuses it when the private key is required.
 *
 * <p>A JavaBean, so a configuration binder can populate it. Not thread-safe.
 */
public final class LinuxOpenSslProviderOptions {
    private String provider = "tpm2";
    private String keyUri;
    private String certificateFile;

    /** Options for the tpm2 provider, with no key or certificate yet. */
    public LinuxOpenSslProviderOptions() {
    }

    /** {@return the OpenSSL provider that holds the key: "tpm2" (the default) or "pkcs11"} */
    public String getProvider() {
        return provider;
    }

    /**
     * Sets the OpenSSL provider that holds the key.
     *
     * @param provider the OpenSSL provider that holds the key
     */
    public void setProvider(String provider) {
        this.provider = provider;
    }

    /**
     * The key, as the provider names it: {@code "handle:0x81000001"} for a persistent TPM key, a
     * path to a TPM key blob, or a {@code "pkcs11:"} URI.
     *
     * @return the key's URI, or {@code null} when unset
     */
    public String getKeyUri() {
        return keyUri;
    }

    /**
     * Sets the key, as the provider names it.
     *
     * @param keyUri the key, as the provider names it
     */
    public void setKeyUri(String keyUri) {
        this.keyUri = keyUri;
    }

    /** {@return the certificate, PEM-encoded, without its key; an absolute path, or {@code null} when unset} */
    public String getCertificateFile() {
        return certificateFile;
    }

    /**
     * Sets the certificate's PEM file, an absolute path.
     *
     * @param certificateFile the certificate's PEM file, an absolute path
     */
    public void setCertificateFile(String certificateFile) {
        this.certificateFile = certificateFile;
    }

    @Override
    public String toString() {
        return "LinuxOpenSslProviderOptions[provider=" + provider + ", keyUri=" + keyUri + ", certificateFile=" + certificateFile + "]";
    }
}
