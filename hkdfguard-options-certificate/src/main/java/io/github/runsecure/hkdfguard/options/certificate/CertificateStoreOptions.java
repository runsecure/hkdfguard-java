package io.github.runsecure.hkdfguard.options.certificate;

/**
 * A certificate in an operating system certificate store, found by its subject, so a renewed
 * certificate an administrator adds under the same subject is picked up with no change to
 * configuration. Of the certificates with that subject, the one opened is the one valid now - and
 * with its private key, when one is required - that expires last; an expired or not-yet-valid one
 * is never chosen. Its private key stays in the store: on Windows the loader holds a CNG or CryptoAPI
 * handle to it, never the key itself.
 *
 * <p>On Java, a store is opened through the JDK's {@code KeyStore}, which has fewer stores than
 * .NET's X509Store: Windows' {@link StoreName#MY My} and {@link StoreName#ROOT Root}, in either
 * location, and on macOS the user's keychain search list and the system roots (see
 * {@link CertificateOptionsValidator} for the exact mapping, and what it refuses).
 *
 * <p>Matching by subject trusts whoever can add a certificate to the store to choose it: keep it to
 * a store only administrators can write, such as LocalMachine's My.
 *
 * <p>A JavaBean, so a configuration binder can populate it. Not thread-safe.
 */
public final class CertificateStoreOptions {
    private StoreLocation storeLocation = StoreLocation.LOCAL_MACHINE;
    private StoreName storeName = StoreName.MY;
    private String subject;

    /** Options for LocalMachine's My store, with no subject yet. */
    public CertificateStoreOptions() {
    }

    /** {@return which store location to open; default {@link StoreLocation#LOCAL_MACHINE}} */
    public StoreLocation getStoreLocation() {
        return storeLocation;
    }

    /**
     * Sets which store location to open.
     *
     * @param storeLocation which store location to open
     */
    public void setStoreLocation(StoreLocation storeLocation) {
        this.storeLocation = storeLocation;
    }

    /** {@return which store to open; default {@link StoreName#MY} (Personal)} */
    public StoreName getStoreName() {
        return storeName;
    }

    /**
     * Sets which store to open.
     *
     * @param storeName which store to open
     */
    public void setStoreName(StoreName storeName) {
        this.storeName = storeName;
    }

    /**
     * The certificate's subject distinguished name, as the certificate states it:
     * {@code "CN=api.example.com, O=Contoso"}. Compared to each certificate's whole subject,
     * attribute by attribute, each value decoded and compared ignoring case - never as a substring,
     * so {@code "CN=api"} doesn't match {@code "CN=api.example.com"}.
     *
     * @return the subject, or {@code null} when unset
     */
    public String getSubject() {
        return subject;
    }

    /**
     * Sets the certificate's subject distinguished name.
     *
     * @param subject the certificate's subject distinguished name
     */
    public void setSubject(String subject) {
        this.subject = subject;
    }

    @Override
    public String toString() {
        return "CertificateStoreOptions[storeLocation=" + storeLocation + ", storeName=" + storeName + ", subject=" + subject + "]";
    }
}
