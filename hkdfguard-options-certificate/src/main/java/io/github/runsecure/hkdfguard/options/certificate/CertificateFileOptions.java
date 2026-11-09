package io.github.runsecure.hkdfguard.options.certificate;

/**
 * A certificate and its key read from files, absolute paths. The key must be protected by a
 * password - a password-protected PKCS#12 file, or an encrypted PKCS#8 PEM key - and the password
 * comes from the secret {@link #getPasswordSecretName()} names, never from configuration. An
 * unprotected key file is refused unless {@link #isAllowUnprotectedPrivateKey()} is set.
 *
 * <p>A JavaBean, so a configuration binder can populate it. Not thread-safe.
 */
public final class CertificateFileOptions {
    private String path;
    private CertificateFileFormat format = CertificateFileFormat.PKCS12;
    private String keyPath;
    private String passwordSecretName;
    private boolean allowUnprotectedPrivateKey;

    /** Options for a PKCS#12 file, with no path yet. */
    public CertificateFileOptions() {
    }

    /** {@return the certificate file - PKCS#12, or a PEM certificate; {@code null} when unset} */
    public String getPath() {
        return path;
    }

    /**
     * Sets the certificate file, an absolute path.
     *
     * @param path the certificate file, an absolute path
     */
    public void setPath(String path) {
        this.path = path;
    }

    /** {@return the file's format; default {@link CertificateFileFormat#PKCS12}} */
    public CertificateFileFormat getFormat() {
        return format;
    }

    /**
     * Sets the file's format.
     *
     * @param format the file's format
     */
    public void setFormat(CertificateFileFormat format) {
        this.format = format;
    }

    /** {@return the PEM private key file, for {@link CertificateFileFormat#PEM}; ignored for PKCS#12} */
    public String getKeyPath() {
        return keyPath;
    }

    /**
     * Sets the PEM private key file, an absolute path.
     *
     * @param keyPath the PEM private key file, an absolute path
     */
    public void setKeyPath(String keyPath) {
        this.keyPath = keyPath;
    }

    /**
     * The name of the secret holding the key's password, as a protected secret source - a
     * FilePerSecretCacheImpl, a remote secret cache, systemd credentials - is asked for it. The
     * password is decrypted only while the key is read, into a {@code char[]} zeroed straight after.
     *
     * @return the secret's name, or {@code null} when unset
     */
    public String getPasswordSecretName() {
        return passwordSecretName;
    }

    /**
     * Sets the name of the secret holding the key's password.
     *
     * @param passwordSecretName the name of the secret holding the key's password
     */
    public void setPasswordSecretName(String passwordSecretName) {
        this.passwordSecretName = passwordSecretName;
    }

    /**
     * Accepts a key file with no password - a PKCS#12 file without one, or a plain PEM key - whose
     * private key is then plaintext on disk, protected only by file permissions. Default false; set
     * it only for development.
     *
     * @return whether an unprotected key file is accepted
     */
    public boolean isAllowUnprotectedPrivateKey() {
        return allowUnprotectedPrivateKey;
    }

    /**
     * Sets true to accept a key file with no password.
     *
     * @param allowUnprotectedPrivateKey true to accept a key file with no password
     */
    public void setAllowUnprotectedPrivateKey(boolean allowUnprotectedPrivateKey) {
        this.allowUnprotectedPrivateKey = allowUnprotectedPrivateKey;
    }

    @Override
    public String toString() {
        return "CertificateFileOptions[path=" + path + ", format=" + format + ", keyPath=" + keyPath + ", passwordSecretName=" + passwordSecretName
                + ", allowUnprotectedPrivateKey=" + allowUnprotectedPrivateKey + "]";
    }
}
