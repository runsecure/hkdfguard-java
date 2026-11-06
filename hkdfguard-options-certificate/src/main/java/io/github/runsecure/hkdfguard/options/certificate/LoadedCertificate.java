package io.github.runsecure.hkdfguard.options.certificate;

import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.DestroyFailedException;

/**
 * The certificate {@link CertificateOptionsLoader} opened - Java's counterpart of the
 * X509Certificate2 .NET's loader returns: the leaf {@link X509Certificate}, its chain where the
 * source gives one, and its {@link PrivateKey} when {@link CertificateOptions#isRequirePrivateKey()}
 * asked for it. The caller owns it, and closes it.
 *
 * <p>A key from a certificate store stays in the store: on Windows it is SunMSCAPI's handle to the
 * CNG or CryptoAPI key, never the key's bytes, and every signature it makes is made by Windows. A key
 * from a file is a JDK software key.
 *
 * <p>For TLS, {@link #createKeyManager()} presents this certificate and key, and
 * {@link #createSslContext(TrustManager...)} builds an {@link SSLContext} around it - neither copies
 * the key into a KeyStore, so a store's key handle works as well as a software key.
 *
 * <p>{@link #close()} destroys the private key where the key allows it and drops every reference;
 * afterwards every accessor throws {@link IllegalStateException}, and a key manager made from it
 * presents nothing. Most JDK private keys - software RSA and EC keys, and SunMSCAPI's handles, which
 * are released when collected - don't implement destroying, so close is a best effort for the key
 * itself; it never fails for that.
 */
public final class LoadedCertificate implements AutoCloseable {
    private static final String ALIAS = "hkdfguard";

    private final X509Certificate certificate;
    private volatile List<X509Certificate> chain;
    private volatile PrivateKey privateKey;
    private volatile boolean closed;

    LoadedCertificate(X509Certificate certificate, List<X509Certificate> chain, PrivateKey privateKey) {
        this.certificate = Objects.requireNonNull(certificate, "certificate");
        this.chain = chain == null || chain.isEmpty() ? List.of(certificate) : List.copyOf(chain);
        this.privateKey = privateKey;
    }

    /**
     * {@return the leaf certificate}
     * @throws IllegalStateException the certificate has been closed
     */
    public X509Certificate getCertificate() {
        requireOpen();
        return certificate;
    }

    /**
     * The certificate chain, leaf first: as the store or file gave it - a store's chain to its
     * root, a PKCS#12 file's chain, every certificate of a PEM file - or the leaf alone when it gave
     * none.
     *
     * @return the chain, leaf first; never empty
     * @throws IllegalStateException the certificate has been closed
     */
    public List<X509Certificate> getCertificateChain() {
        requireOpen();
        return chain;
    }

    /**
     * {@return the private key, or {@code null} when it wasn't required}
     * @throws IllegalStateException the certificate has been closed
     */
    public PrivateKey getPrivateKey() {
        requireOpen();
        return privateKey;
    }

    /**
     * {@return whether a private key was loaded with the certificate}
     * @throws IllegalStateException the certificate has been closed
     */
    public boolean hasPrivateKey() {
        requireOpen();
        return privateKey != null;
    }

    /** {@return whether {@link #close()} has been called} */
    public boolean isClosed() {
        return closed;
    }

    /**
     * A key manager that presents this certificate, its chain and its private key - and nothing
     * else - for every key type the key is, to a TLS server or client. It reads from this object, so
     * once it is closed the key manager presents nothing and the handshake fails.
     *
     * @return the key manager
     * @throws IllegalStateException the certificate has been closed, or has no private key
     */
    public X509ExtendedKeyManager createKeyManager() {
        requireOpen();
        if (privateKey == null)
            throw new IllegalStateException("The certificate '" + certificate.getSubjectX500Principal() + "' has no private key to present.");
        return new KeyManagerImpl();
    }

    /**
     * An {@link SSLContext} for the "TLS" protocol whose key manager is {@link #createKeyManager()}.
     *
     * @param trustManagers the trust managers to verify peers with; none for the JDK's default
     * @return the initialized context
     * @throws IllegalStateException  the certificate has been closed, or has no private key
     * @throws CryptographicException the JDK can't make a TLS context
     */
    public SSLContext createSslContext(TrustManager... trustManagers) {
        var keyManager = createKeyManager();
        try {
            var context = SSLContext.getInstance("TLS");
            context.init(new KeyManager[] { keyManager }, trustManagers == null || trustManagers.length == 0 ? null : trustManagers, null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new CryptographicException("A TLS context couldn't be made for the certificate: " + e.getMessage(), e);
        }
    }

    /** Destroys the private key where it allows it, and drops the key and chain. Safe to call more than once. */
    @Override
    public void close() {
        closed = true;
        var key = privateKey;
        privateKey = null;
        chain = List.of();
        if (key != null && !key.isDestroyed()) {
            try {
                key.destroy();
            } catch (DestroyFailedException | UnsupportedOperationException e) {
                // Most JDK keys can't be destroyed; dropping the reference is all there is.
            }
        }
    }

    private void requireOpen() {
        if (closed)
            throw new IllegalStateException("The certificate has been closed.");
    }

    // Whether the key is what JSSE asks for: its algorithm name ("RSA", "EC", "EdDSA"...).
    private boolean presents(String keyType) {
        var key = privateKey;
        return !closed && key != null && keyType != null && keyType.equalsIgnoreCase(key.getAlgorithm());
    }

    private String aliasFor(String[] keyTypes) {
        if (keyTypes != null) {
            for (var keyType : keyTypes) {
                if (presents(keyType))
                    return ALIAS;
            }
        }
        return null;
    }

    private final class KeyManagerImpl extends X509ExtendedKeyManager {
        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return presents(keyType) ? new String[] { ALIAS } : null;
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return aliasFor(keyType);
        }

        @Override
        public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
            return aliasFor(keyType);
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return presents(keyType) ? new String[] { ALIAS } : null;
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return presents(keyType) ? ALIAS : null;
        }

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            return presents(keyType) ? ALIAS : null;
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            var current = chain;
            return ALIAS.equals(alias) && !closed && !current.isEmpty() ? current.toArray(X509Certificate[]::new) : null;
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return ALIAS.equals(alias) && !closed ? privateKey : null;
        }
    }
}
