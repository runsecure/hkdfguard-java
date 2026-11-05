package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Which certificates a {@link VaultClient} - or the HashiCorp Vault transit key wrapper or secret
 * cache - trusts Vault's to be signed by, and which it presents for the cert auth method
 * (https://developer.hashicorp.com/vault/docs/auth/cert) or a Vault requiring mutual TLS. All unset,
 * the JDK's default trust store decides. Immutable: build one with {@link #builder()}. Files are read
 * when the client is created.
 * <p>
 * Certificates are PEM ("CERTIFICATE" blocks). A client key is a PEM "PRIVATE KEY" (PKCS#8),
 * "RSA PRIVATE KEY" (PKCS#1) or "EC PRIVATE KEY" (SEC1, with a named curve) - unencrypted, as
 * vault-client-go reads it.
 * <p>
 * Either can instead come from a password-protected key store, PKCS#12 or JKS: a trust store
 * ({@link #trustStoreFile()}) in place of the PEM CA certificates, a client key store
 * ({@link #clientKeyStoreFile()}) in place of the PEM client certificate and key. A store's
 * password is held only protected, by a protector on the key ring
 * ({@code keyRing.createProtector(PASSWORD_PURPOSE)}, set as {@link #passwordProtector()}): it is
 * decrypted into a char array only while the store is read, and zeroed at once.
 */
public final class VaultTlsOptions {
    private static final Pattern PEM_BLOCK = Pattern.compile("-----BEGIN ([A-Z0-9 ]+)-----([A-Za-z0-9+/=\\s]*)-----END \\1-----");
    private static final Pattern IPV4_LITERAL = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");
    private static final String CLIENT_ALIAS = "vault-client";

    /**
     * The purpose to create the key store password protector with -
     * {@code keyRing.createProtector(PASSWORD_PURPOSE)} - so a password protected for TLS can't be
     * decrypted as anything else, nor anything else as it.
     */
    public static final String PASSWORD_PURPOSE = "HkdfGuard.Integration.HashiCorpVault.KeyStorePassword";

    private final Path serverCertificateFile;
    private final byte[] serverCertificatePem;
    private final Path serverCertificateDirectory;
    private final Path clientCertificateFile;
    private final byte[] clientCertificatePem;
    private final Path clientCertificateKeyFile;
    private final byte[] clientCertificateKeyPem;
    private final String serverName;
    private final boolean insecureSkipVerify;
    private final Path trustStoreFile;
    private final String trustStorePassword;
    private final Path clientKeyStoreFile;
    private final String clientKeyStorePassword;
    private final String clientKeyStoreAlias;
    private final DataProtector passwordProtector;

    private VaultTlsOptions(Builder builder) {
        serverCertificateFile = builder.serverCertificateFile;
        serverCertificatePem = builder.serverCertificatePem;
        serverCertificateDirectory = builder.serverCertificateDirectory;
        clientCertificateFile = builder.clientCertificateFile;
        clientCertificatePem = builder.clientCertificatePem;
        clientCertificateKeyFile = builder.clientCertificateKeyFile;
        clientCertificateKeyPem = builder.clientCertificateKeyPem;
        serverName = builder.serverName;
        insecureSkipVerify = builder.insecureSkipVerify;
        trustStoreFile = builder.trustStoreFile;
        trustStorePassword = builder.trustStorePassword;
        clientKeyStoreFile = builder.clientKeyStoreFile;
        clientKeyStorePassword = builder.clientKeyStorePassword;
        clientKeyStoreAlias = builder.clientKeyStoreAlias;
        passwordProtector = builder.passwordProtector;
    }

    /** A builder holding the defaults: nothing set. */
    public static Builder builder() {
        return new Builder();
    }

    /** A builder holding these options, to change some of them. */
    public Builder toBuilder() {
        return new Builder()
                .serverCertificateFile(serverCertificateFile)
                .serverCertificatePem(serverCertificatePem)
                .serverCertificateDirectory(serverCertificateDirectory)
                .clientCertificateFile(clientCertificateFile)
                .clientCertificatePem(clientCertificatePem)
                .clientCertificateKeyFile(clientCertificateKeyFile)
                .clientCertificateKeyPem(clientCertificateKeyPem)
                .serverName(serverName)
                .insecureSkipVerify(insecureSkipVerify)
                .trustStoreFile(trustStoreFile)
                .trustStorePassword(trustStorePassword)
                .clientKeyStoreFile(clientKeyStoreFile)
                .clientKeyStorePassword(clientKeyStorePassword)
                .clientKeyStoreAlias(clientKeyStoreAlias)
                .passwordProtector(passwordProtector);
    }

    /**
     * Protects password with passwordProtector - a protector on the key ring,
     * {@code keyRing.createProtector(PASSWORD_PURPOSE)} - for {@link Builder#trustStorePassword} or
     * {@link Builder#clientKeyStorePassword}. password is read, never kept or cleared: zero it once
     * this returns.
     *
     * @throws NullPointerException     passwordProtector or password is null
     * @throws IllegalArgumentException password is empty
     */
    public static String protectPassword(DataProtector passwordProtector, char[] password) {
        Objects.requireNonNull(passwordProtector, "passwordProtector");
        Objects.requireNonNull(password, "password");
        if (password.length == 0)
            throw new IllegalArgumentException("A key store password can't be empty.");
        return passwordProtector.encrypt(CharBuffer.wrap(password));
    }

    /** A PEM file of the CA certificate(s) Vault's certificate must chain to - VAULT_CACERT. Takes precedence over the PEM and directory. */
    public Path serverCertificateFile() {
        return serverCertificateFile;
    }

    /** PEM-encoded CA certificate(s) - VAULT_CACERT_BYTES; a copy. Takes precedence over the directory. */
    public byte[] serverCertificatePem() {
        return serverCertificatePem == null ? null : serverCertificatePem.clone();
    }

    /** A directory of PEM-encoded CA certificates - VAULT_CAPATH. Every file in it must hold at least one. */
    public Path serverCertificateDirectory() {
        return serverCertificateDirectory;
    }

    /** A PEM file of the client certificate - VAULT_CLIENT_CERT. Takes precedence over the PEM; needs a key. */
    public Path clientCertificateFile() {
        return clientCertificateFile;
    }

    /** The PEM-encoded client certificate, a copy; needs a key. */
    public byte[] clientCertificatePem() {
        return clientCertificatePem == null ? null : clientCertificatePem.clone();
    }

    /** A PEM file of the client certificate's private key - VAULT_CLIENT_KEY. Takes precedence over the PEM. */
    public Path clientCertificateKeyFile() {
        return clientCertificateKeyFile;
    }

    /** The client certificate's PEM-encoded private key, a copy. */
    public byte[] clientCertificateKeyPem() {
        return clientCertificateKeyPem == null ? null : clientCertificateKeyPem.clone();
    }

    /**
     * The name Vault's certificate must be issued to, when it isn't the address's host (connecting by
     * IP, say) - VAULT_TLS_SERVER_NAME. Only verification uses it: the TLS handshake still names the
     * address's host.
     */
    public String serverName() {
        return serverName;
    }

    /**
     * Accepts any certificate Vault presents - VAULT_SKIP_VERIFY. Anyone between the client and
     * Vault can then read every token and secret: for a throwaway dev server only.
     */
    public boolean insecureSkipVerify() {
        return insecureSkipVerify;
    }

    /**
     * A key store - PKCS#12 or JKS - of the CA certificates Vault's certificate must chain to, its
     * trusted-certificate entries; needs {@link #trustStorePassword()}. Can't be combined with the PEM
     * CA certificates.
     */
    public Path trustStoreFile() {
        return trustStoreFile;
    }

    /** {@link #trustStoreFile()}'s password, protected by {@link #passwordProtector()} ({@link #protectPassword}). */
    public String trustStorePassword() {
        return trustStorePassword;
    }

    /**
     * A key store - PKCS#12 or JKS - holding the client certificate's private key and chain; needs
     * {@link #clientKeyStorePassword()}. Can't be combined with the PEM client certificate and key.
     */
    public Path clientKeyStoreFile() {
        return clientKeyStoreFile;
    }

    /**
     * {@link #clientKeyStoreFile()}'s password, protected by {@link #passwordProtector()}
     * ({@link #protectPassword}). It unlocks the private key too, as PKCS#12 requires.
     */
    public String clientKeyStorePassword() {
        return clientKeyStorePassword;
    }

    /** The private key entry {@link #clientKeyStoreFile()} presents; null when it holds only one. */
    public String clientKeyStoreAlias() {
        return clientKeyStoreAlias;
    }

    /**
     * Decrypts the key store passwords: a protector on the key ring,
     * {@code keyRing.createProtector(PASSWORD_PURPOSE)}.
     */
    public DataProtector passwordProtector() {
        return passwordProtector;
    }

    /** Whether nothing is set, so the JDK's defaults decide. */
    public boolean isEmpty() {
        return serverCertificateFile == null && isEmpty(serverCertificatePem) && serverCertificateDirectory == null
                && clientCertificateFile == null && isEmpty(clientCertificatePem)
                && clientCertificateKeyFile == null && isEmpty(clientCertificateKeyPem)
                && serverName == null && !insecureSkipVerify
                && trustStoreFile == null && clientKeyStoreFile == null;
    }

    /**
     * An SSLContext trusting and presenting what these options say.
     *
     * @throws IllegalArgumentException a certificate, key or key store can't be read; a client
     *                                  certificate has no key or a key no certificate; a key store has
     *                                  no password, or one passwordProtector didn't protect; or a key
     *                                  store is combined with the PEM it replaces
     */
    SSLContext createSslContext() {
        try {
            var context = SSLContext.getInstance("TLS");
            context.init(clientKeyManager(), trustManagers(), null);
            return context;
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException("Could not set up TLS: " + e.getMessage(), e);
        }
    }

    private TrustManager[] trustManagers() throws GeneralSecurityException {
        if (insecureSkipVerify)
            return new TrustManager[] {new InsecureTrustManager()};

        var roots = serverCertificates();
        if (roots == null && serverName == null)
            return null;

        var factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        if (roots == null) {
            factory.init((KeyStore) null);
        } else {
            var store = emptyKeyStore();
            for (var i = 0; i < roots.size(); i++)
                store.setCertificateEntry("ca-" + i, roots.get(i));
            factory.init(store);
        }

        var managers = factory.getTrustManagers();
        if (serverName == null)
            return managers;

        for (var manager : managers) {
            if (manager instanceof X509TrustManager x509)
                return new TrustManager[] {new ServerNameTrustManager(x509, serverName)};
        }
        throw new GeneralSecurityException("The JDK has no X.509 trust manager.");
    }

    private List<X509Certificate> serverCertificates() throws GeneralSecurityException {
        if (trustStoreFile != null) {
            if (serverCertificateFile != null || !isEmpty(serverCertificatePem) || serverCertificateDirectory != null)
                throw new IllegalArgumentException("A trust store and PEM CA certificates can't be given together.");
            return trustStoreCertificates();
        }

        var roots = new ArrayList<X509Certificate>();
        if (serverCertificateFile != null) {
            importCertificates(roots, read(serverCertificateFile), serverCertificateFile.toString());
        } else if (!isEmpty(serverCertificatePem)) {
            importCertificates(roots, serverCertificatePem, "serverCertificatePem");
        } else if (serverCertificateDirectory != null) {
            try (Stream<Path> files = Files.list(serverCertificateDirectory)) {
                for (var file : files.filter(Files::isRegularFile).sorted().toList())
                    importCertificates(roots, read(file), file.toString());
            } catch (IOException e) {
                throw new IllegalArgumentException("Could not list the CA certificates in " + serverCertificateDirectory + ": " + e.getMessage(), e);
            }
        } else {
            return null;
        }
        return roots;
    }

    private static void importCertificates(List<X509Certificate> roots, byte[] pem, String source) {
        var before = roots.size();
        try {
            roots.addAll(certificates(pem));
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Could not read the CA certificate(s) in " + source + ": " + e.getMessage(), e);
        }
        if (roots.size() == before)
            throw new IllegalArgumentException(source + " holds no PEM-encoded certificate.");
    }

    // The trusted-certificate entries of the trust store.
    private List<X509Certificate> trustStoreCertificates() throws GeneralSecurityException {
        return withKeyStore(trustStoreFile, trustStorePassword, "trust store", (store, password) -> {
            var roots = new ArrayList<X509Certificate>();
            for (var name : Collections.list(store.aliases())) {
                if (store.isCertificateEntry(name) && store.getCertificate(name) instanceof X509Certificate certificate)
                    roots.add(certificate);
            }
            if (roots.isEmpty())
                throw new IllegalArgumentException("The trust store " + trustStoreFile + " holds no trusted certificate.");
            return roots;
        });
    }

    private record ClientKey(List<X509Certificate> chain, PrivateKey key) {
    }

    private X509ExtendedKeyManager[] clientKeyManager() throws GeneralSecurityException {
        var hasCertificate = clientCertificateFile != null || !isEmpty(clientCertificatePem);
        var hasKey = clientCertificateKeyFile != null || !isEmpty(clientCertificateKeyPem);
        if (clientKeyStoreFile != null && (hasCertificate || hasKey))
            throw new IllegalArgumentException("A client key store and a PEM client certificate or key can't be given together.");
        if (hasCertificate != hasKey)
            throw new IllegalArgumentException("A client certificate and its key must be given together.");
        if (!hasCertificate && clientKeyStoreFile == null)
            return null;

        var client = clientKeyStoreFile != null ? clientKeyFromStore() : clientKeyFromPem();
        var store = emptyKeyStore();
        var password = new char[0];
        store.setKeyEntry(CLIENT_ALIAS, client.key(), password, client.chain().toArray(X509Certificate[]::new));
        var factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(store, password);
        for (var manager : factory.getKeyManagers()) {
            if (manager instanceof X509ExtendedKeyManager x509)
                return new X509ExtendedKeyManager[] {new ClientKeyManager(x509)};
        }
        throw new GeneralSecurityException("The JDK has no X.509 key manager.");
    }

    private ClientKey clientKeyFromPem() {
        var certificatePem = clientCertificateFile != null ? read(clientCertificateFile) : clientCertificatePem;
        var keyPem = clientCertificateKeyFile != null ? read(clientCertificateKeyFile) : clientCertificateKeyPem;
        List<X509Certificate> chain;
        PrivateKey key;
        try {
            chain = certificates(certificatePem);
            key = privateKey(keyPem);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalArgumentException("Could not read the client certificate and key: " + e.getMessage(), e);
        }
        if (chain.isEmpty())
            throw new IllegalArgumentException("Could not read the client certificate and key: the certificate PEM holds no certificate.");
        return new ClientKey(chain, key);
    }

    // The client key store's private key entry: the one named clientKeyStoreAlias, or its only one.
    private ClientKey clientKeyFromStore() throws GeneralSecurityException {
        return withKeyStore(clientKeyStoreFile, clientKeyStorePassword, "client key store", (store, password) -> {
            var alias = clientKeyStoreAlias;
            if (alias == null) {
                for (var name : Collections.list(store.aliases())) {
                    if (!store.entryInstanceOf(name, KeyStore.PrivateKeyEntry.class))
                        continue;
                    if (alias != null)
                        throw new IllegalArgumentException("The client key store " + clientKeyStoreFile
                                + " holds more than one private key: name the one to present with clientKeyStoreAlias.");
                    alias = name;
                }
                if (alias == null)
                    throw new IllegalArgumentException("The client key store " + clientKeyStoreFile + " holds no private key.");
            } else if (!store.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
                throw new IllegalArgumentException("The client key store " + clientKeyStoreFile + " holds no private key named '" + alias + "'.");
            }

            // The store's password unlocks the key too, as PKCS#12 requires.
            var key = (PrivateKey) store.getKey(alias, password);
            var chain = new ArrayList<X509Certificate>();
            for (var certificate : store.getCertificateChain(alias)) {
                if (!(certificate instanceof X509Certificate x509))
                    throw new IllegalArgumentException("The client key store " + clientKeyStoreFile + " holds a certificate that isn't X.509.");
                chain.add(x509);
            }
            return new ClientKey(chain, key);
        });
    }

    private interface KeyStoreUse<T> {
        T apply(KeyStore store, char[] password) throws GeneralSecurityException;
    }

    // Reads file - PKCS#12 or JKS, whichever it is - unlocked with the password protectedPassword
    // holds, and hands it and the password to use. The password is decrypted only for that, and
    // zeroed once it returns.
    private <T> T withKeyStore(Path file, String protectedPassword, String what, KeyStoreUse<T> use) throws GeneralSecurityException {
        if (protectedPassword == null || protectedPassword.isEmpty())
            throw new IllegalArgumentException("The " + what + " " + file + " needs its password, protected: VaultTlsOptions.protectPassword.");
        if (passwordProtector == null)
            throw new IllegalArgumentException("The " + what + "'s password needs the protector that protected it: set passwordProtector.");

        var password = decryptPassword(protectedPassword, what);
        try {
            KeyStore store;
            try {
                store = KeyStore.getInstance(file.toFile(), password);
            } catch (IOException e) {
                // A wrong password is reported as an IOException too.
                throw new IllegalArgumentException("Could not read the " + what + " " + file + ": " + e.getMessage(), e);
            }
            return use.apply(store, password);
        } finally {
            ArrayUtility.zeroMemory(password);
        }
    }

    // The password protectedPassword holds, in an array exactly its length that the caller zeroes.
    // The protector's exceptions aren't chained: a parser handed an unprotected password could
    // quote it.
    private char[] decryptPassword(String protectedPassword, String what) {
        int maxLength;
        try {
            maxLength = passwordProtector.getMaxDecryptedLength(protectedPassword);
        } catch (IllegalArgumentException | CryptographicException | NoSuchElementException e) {
            throw notProtected(what);
        }
        if (maxLength < 0)
            throw notProtected(what);

        var chars = new char[maxLength];
        try {
            int length;
            try {
                length = passwordProtector.decrypt(protectedPassword, chars);
            } catch (IllegalArgumentException | CryptographicException | NoSuchElementException e) {
                throw notProtected(what);
            }
            return Arrays.copyOf(chars, length);
        } finally {
            ArrayUtility.zeroMemory(chars);
        }
    }

    private static IllegalArgumentException notProtected(String what) {
        return new IllegalArgumentException("The " + what + "'s password isn't protected by passwordProtector: "
                + "give VaultTlsOptions.protectPassword(passwordProtector, password), never the password itself.");
    }

    // An in-memory key store, empty.
    private static KeyStore emptyKeyStore() throws GeneralSecurityException {
        var store = KeyStore.getInstance("PKCS12");
        try {
            store.load(null, null);
        } catch (IOException e) {
            // Nothing is read: an empty store has no input to fail on.
            throw new UncheckedIOException(e);
        }
        return store;
    }

    private static List<X509Certificate> certificates(byte[] pem) throws CertificateException {
        var factory = CertificateFactory.getInstance("X.509");
        var certificates = new ArrayList<X509Certificate>();
        for (var block : pemBlocks(pem)) {
            if (block.label().equals("CERTIFICATE"))
                certificates.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(block.der())));
        }
        return certificates;
    }

    private static PrivateKey privateKey(byte[] pem) throws GeneralSecurityException {
        for (var block : pemBlocks(pem)) {
            var pkcs8 = switch (block.label()) {
                case "PRIVATE KEY" -> block.der();
                case "RSA PRIVATE KEY" -> Der.rsaToPkcs8(block.der());
                case "EC PRIVATE KEY" -> Der.ecToPkcs8(block.der());
                case "ENCRYPTED PRIVATE KEY" -> throw new IllegalArgumentException("the key is encrypted; give it unencrypted, as vault-client-go reads it");
                default -> null;
            };
            if (pkcs8 == null)
                continue;

            for (var algorithm : List.of("RSA", "EC", "Ed25519", "Ed448", "RSASSA-PSS")) {
                try {
                    return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
                } catch (GeneralSecurityException ignored) {
                    // Another algorithm's key.
                }
            }
            throw new IllegalArgumentException("the private key's algorithm isn't RSA, EC or EdDSA");
        }
        throw new IllegalArgumentException("the key PEM holds no private key");
    }

    private record PemBlock(String label, byte[] der) {
        @Override
        public boolean equals(Object other) {
            return other instanceof PemBlock that && Objects.equals(label, that.label) && Arrays.equals(der, that.der);
        }

        @Override
        public int hashCode() {
            return 31 * Objects.hashCode(label) + Arrays.hashCode(der);
        }

        // The DER may be a private key: only its length is shown.
        @Override
        public String toString() {
            return "PemBlock[label=" + label + ", length=" + der.length + "]";
        }
    }

    private static List<PemBlock> pemBlocks(byte[] pem) {
        var blocks = new ArrayList<PemBlock>();
        var matcher = PEM_BLOCK.matcher(new String(pem, StandardCharsets.US_ASCII));
        while (matcher.find())
            blocks.add(new PemBlock(matcher.group(1), Base64.getMimeDecoder().decode(matcher.group(2))));
        return blocks;
    }

    private static byte[] read(Path file) {
        try {
            return Files.readAllBytes(file);
        } catch (IOException e) {
            throw new IllegalArgumentException("Could not read " + file + ": " + e.getMessage(), e);
        }
    }

    private static boolean isEmpty(byte[] bytes) {
        return bytes == null || bytes.length == 0;
    }

    /**
     * Whether certificate is issued to name, as Go's VerifyHostname decides: an IP literal against
     * the certificate's IP addresses, any other name against its DNS names (a "*." wildcard matching
     * one leftmost label), case-insensitively. Its subject's common name doesn't count.
     */
    static boolean matchesHostname(X509Certificate certificate, String name) {
        java.util.Collection<List<?>> alternatives;
        try {
            alternatives = certificate.getSubjectAlternativeNames();
        } catch (CertificateParsingException e) {
            return false;
        }
        if (alternatives == null)
            return false;

        var host = name.endsWith(".") ? name.substring(0, name.length() - 1) : name;
        if (host.startsWith("[") && host.endsWith("]"))
            host = host.substring(1, host.length() - 1);
        var ip = IPV4_LITERAL.matcher(host).matches() || host.contains(":") ? literal(host) : null;

        for (var alternative : alternatives) {
            var type = (Integer) alternative.get(0);
            var value = String.valueOf(alternative.get(1));
            if (ip != null) {
                if (type == 7 && ip.equals(literal(value)))
                    return true;
            } else if (type == 2 && matchesDnsName(value, host)) {
                return true;
            }
        }
        return false;
    }

    private static boolean matchesDnsName(String pattern, String host) {
        pattern = pattern.toLowerCase(Locale.ROOT);
        host = host.toLowerCase(Locale.ROOT);
        if (pattern.endsWith("."))
            pattern = pattern.substring(0, pattern.length() - 1);
        if (!pattern.startsWith("*."))
            return pattern.equals(host);

        var dot = host.indexOf('.');
        return dot > 0 && host.substring(dot).equals(pattern.substring(1));
    }

    // An IP literal's address, never resolving a name: callers pass only literals.
    private static InetAddress literal(String ip) {
        try {
            return InetAddress.getByName(ip);
        } catch (UnknownHostException e) {
            return null;
        }
    }

    /** Trusts what the JDK's trust manager trusts, but checks the name against serverName rather than the address's host. */
    private static final class ServerNameTrustManager extends X509ExtendedTrustManager {
        private final X509TrustManager trust;
        private final String serverName;

        ServerNameTrustManager(X509TrustManager trust, String serverName) {
            this.trust = trust;
            this.serverName = serverName;
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            // The two-argument check verifies the chain, never a host name.
            trust.checkServerTrusted(chain, authType);
            if (!matchesHostname(chain[0], serverName))
                throw new CertificateException("Vault's certificate isn't issued to '" + serverName + "' (VAULT_TLS_SERVER_NAME).");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            checkServerTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            checkServerTrusted(chain, authType);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("A Vault client authenticates no clients.");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            checkClientTrusted(chain, authType);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            checkClientTrusted(chain, authType);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return trust.getAcceptedIssuers();
        }
    }

    /** Accepts any certificate: insecureSkipVerify. */
    private static final class InsecureTrustManager extends X509ExtendedTrustManager {
        @Override
        @SuppressWarnings("java:S4830")
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // insecureSkipVerify: accepted unchecked, as the option says.
        }

        @Override
        @SuppressWarnings("java:S4830")
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {
            // insecureSkipVerify.
        }

        @Override
        @SuppressWarnings("java:S4830")
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {
            // insecureSkipVerify.
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("A Vault client authenticates no clients.");
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            checkClientTrusted(chain, authType);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            checkClientTrusted(chain, authType);
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    /**
     * Presents the client certificate whatever CAs Vault says it accepts, as vault-client-go does:
     * the cert auth method's CAs needn't be in the server's own list.
     */
    private static final class ClientKeyManager extends X509ExtendedKeyManager {
        private final X509ExtendedKeyManager keys;

        ClientKeyManager(X509ExtendedKeyManager keys) {
            this.keys = keys;
        }

        @Override
        public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
            return CLIENT_ALIAS;
        }

        @Override
        public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
            return CLIENT_ALIAS;
        }

        @Override
        public String[] getClientAliases(String keyType, Principal[] issuers) {
            return new String[] {CLIENT_ALIAS};
        }

        @Override
        public String[] getServerAliases(String keyType, Principal[] issuers) {
            return null;
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
            return null;
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return keys.getCertificateChain(alias);
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            return keys.getPrivateKey(alias);
        }
    }

    /** Just enough DER to wrap a PKCS#1 or SEC1 key in PKCS#8. */
    private static final class Der {
        private static final byte[] RSA_ALGORITHM = {
            0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00};
        private static final byte[] EC_PUBLIC_KEY_OID = {0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01};
        private static final byte[] VERSION_0 = {0x02, 0x01, 0x00};

        static byte[] rsaToPkcs8(byte[] pkcs1) {
            return sequence(VERSION_0, RSA_ALGORITHM, tlv(0x04, pkcs1));
        }

        // ECPrivateKey ::= SEQUENCE { version, privateKey OCTET STRING, [0] parameters, [1] publicKey }
        static byte[] ecToPkcs8(byte[] sec1) {
            var curve = curveOid(sec1);
            return sequence(VERSION_0, sequence(EC_PUBLIC_KEY_OID, curve), tlv(0x04, sec1));
        }

        private static byte[] curveOid(byte[] sec1) {
            var position = new int[] {0};
            var outer = header(sec1, position, 0x30);
            var end = position[0] + outer;
            while (position[0] < end) {
                var tag = sec1[position[0]] & 0xFF;
                var start = position[0];
                var length = header(sec1, position, tag);
                if (tag == 0xA0) {
                    var oidStart = position[0];
                    var oidLength = header(sec1, position, 0x06);
                    var oid = new byte[position[0] - oidStart + oidLength];
                    System.arraycopy(sec1, oidStart, oid, 0, oid.length);
                    return oid;
                }
                position[0] += length;
                if (position[0] <= start)
                    break;
            }
            throw new IllegalArgumentException("the EC private key names no curve");
        }

        // Reads a tag (which must be expected) and length at position[0], leaving it at the contents.
        private static int header(byte[] der, int[] position, int expected) {
            var p = position[0];
            if (p + 2 > der.length || (der[p] & 0xFF) != expected)
                throw new IllegalArgumentException("the private key isn't DER");
            p++;
            int length = der[p++] & 0xFF;
            if (length > 0x80) {
                var bytes = length - 0x80;
                if (bytes > 3 || p + bytes > der.length)
                    throw new IllegalArgumentException("the private key isn't DER");
                length = 0;
                for (var i = 0; i < bytes; i++)
                    length = length << 8 | (der[p++] & 0xFF);
            } else if (length == 0x80) {
                throw new IllegalArgumentException("the private key isn't DER");
            }
            if (p + length > der.length)
                throw new IllegalArgumentException("the private key isn't DER");
            position[0] = p;
            return length;
        }

        private static byte[] sequence(byte[]... parts) {
            var total = 0;
            for (var part : parts)
                total += part.length;
            var contents = new byte[total];
            var offset = 0;
            for (var part : parts) {
                System.arraycopy(part, 0, contents, offset, part.length);
                offset += part.length;
            }
            return tlv(0x30, contents);
        }

        private static byte[] tlv(int tag, byte[] contents) {
            var length = contents.length;
            byte[] header;
            if (length < 0x80)
                header = new byte[] {(byte) tag, (byte) length};
            else if (length < 0x100)
                header = new byte[] {(byte) tag, (byte) 0x81, (byte) length};
            else if (length < 0x10000)
                header = new byte[] {(byte) tag, (byte) 0x82, (byte) (length >> 8), (byte) length};
            else
                header = new byte[] {(byte) tag, (byte) 0x83, (byte) (length >> 16), (byte) (length >> 8), (byte) length};

            var result = new byte[header.length + length];
            System.arraycopy(header, 0, result, 0, header.length);
            System.arraycopy(contents, 0, result, header.length, length);
            return result;
        }
    }

    /** Builds {@link VaultTlsOptions}; nothing starts set. */
    public static final class Builder {
        private Path serverCertificateFile;
        private byte[] serverCertificatePem;
        private Path serverCertificateDirectory;
        private Path clientCertificateFile;
        private byte[] clientCertificatePem;
        private Path clientCertificateKeyFile;
        private byte[] clientCertificateKeyPem;
        private String serverName;
        private boolean insecureSkipVerify;
        private Path trustStoreFile;
        private String trustStorePassword;
        private Path clientKeyStoreFile;
        private String clientKeyStorePassword;
        private String clientKeyStoreAlias;
        private DataProtector passwordProtector;

        private Builder() {
        }

        /** See {@link VaultTlsOptions#serverCertificateFile()}. */
        public Builder serverCertificateFile(Path file) {
            this.serverCertificateFile = file;
            return this;
        }

        /** See {@link VaultTlsOptions#serverCertificatePem()}; copied. */
        public Builder serverCertificatePem(byte[] pem) {
            this.serverCertificatePem = pem == null ? null : pem.clone();
            return this;
        }

        /** See {@link VaultTlsOptions#serverCertificateDirectory()}. */
        public Builder serverCertificateDirectory(Path directory) {
            this.serverCertificateDirectory = directory;
            return this;
        }

        /** See {@link VaultTlsOptions#clientCertificateFile()}. */
        public Builder clientCertificateFile(Path file) {
            this.clientCertificateFile = file;
            return this;
        }

        /** See {@link VaultTlsOptions#clientCertificatePem()}; copied. */
        public Builder clientCertificatePem(byte[] pem) {
            this.clientCertificatePem = pem == null ? null : pem.clone();
            return this;
        }

        /** See {@link VaultTlsOptions#clientCertificateKeyFile()}. */
        public Builder clientCertificateKeyFile(Path file) {
            this.clientCertificateKeyFile = file;
            return this;
        }

        /** See {@link VaultTlsOptions#clientCertificateKeyPem()}; copied. */
        public Builder clientCertificateKeyPem(byte[] pem) {
            this.clientCertificateKeyPem = pem == null ? null : pem.clone();
            return this;
        }

        /** See {@link VaultTlsOptions#serverName()}. */
        public Builder serverName(String serverName) {
            this.serverName = serverName;
            return this;
        }

        /** See {@link VaultTlsOptions#insecureSkipVerify()}. */
        public Builder insecureSkipVerify(boolean insecureSkipVerify) {
            this.insecureSkipVerify = insecureSkipVerify;
            return this;
        }

        /** See {@link VaultTlsOptions#trustStoreFile()}. */
        public Builder trustStoreFile(Path file) {
            this.trustStoreFile = file;
            return this;
        }

        /** See {@link VaultTlsOptions#trustStorePassword()}: the password as {@link #protectPassword} protected it. */
        public Builder trustStorePassword(String protectedPassword) {
            this.trustStorePassword = protectedPassword;
            return this;
        }

        /** See {@link VaultTlsOptions#clientKeyStoreFile()}. */
        public Builder clientKeyStoreFile(Path file) {
            this.clientKeyStoreFile = file;
            return this;
        }

        /** See {@link VaultTlsOptions#clientKeyStorePassword()}: the password as {@link #protectPassword} protected it. */
        public Builder clientKeyStorePassword(String protectedPassword) {
            this.clientKeyStorePassword = protectedPassword;
            return this;
        }

        /** See {@link VaultTlsOptions#clientKeyStoreAlias()}. */
        public Builder clientKeyStoreAlias(String alias) {
            this.clientKeyStoreAlias = alias;
            return this;
        }

        /** See {@link VaultTlsOptions#passwordProtector()}. */
        public Builder passwordProtector(DataProtector passwordProtector) {
            this.passwordProtector = passwordProtector;
            return this;
        }

        public VaultTlsOptions build() {
            return new VaultTlsOptions(this);
        }
    }
}
