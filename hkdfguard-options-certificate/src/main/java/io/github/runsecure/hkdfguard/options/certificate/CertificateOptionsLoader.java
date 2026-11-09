package io.github.runsecure.hkdfguard.options.certificate;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicReference;
import javax.security.auth.x500.X500Principal;

/**
 * Opens the certificate a validated {@link CertificateOptions} describes, as a
 * {@link LoadedCertificate} the caller owns and closes.
 * <ul>
 * <li>A store ({@link CertificateOptions#getWindows() windows}, {@link CertificateOptions#getMacOS()
 * macOS}) is opened through the JDK's KeyStore for it, and of the certificates whose subject is the
 * one named, the one valid now - with its private key, when one is required - that expires last is
 * returned. Only that one's key is asked for, and the store hands over a handle to it (on Windows,
 * SunMSCAPI's CNG or CryptoAPI handle), never the key itself. The loader never writes to the store,
 * though the JDK opens it with whatever access the account has; it has no read-only mode.</li>
 * <li>A Linux OpenSSL provider source ({@link CertificateOptions#getLinux() linux}) gives the PEM
 * certificate alone: the JDK can't open a provider's key, and validation refuses one.</li>
 * <li>A file ({@link CertificateOptions#getFile() file}) is read with its password, which is
 * decrypted from the password source into a {@code char[]} only while the key is read, and zeroed at
 * once; it is never a String. A PKCS#12 file is opened through KeyStore "PKCS12"; a PEM certificate
 * through CertificateFactory, its encrypted PKCS#8 key through EncryptedPrivateKeyInfo and the JDK's
 * PBES2 cipher (PBKDF2 with HMAC-SHA2 and AES only, at most 10,000,000 iterations; any legacy scheme
 * is refused), and the key checked to be the certificate's.</li>
 * </ul>
 * Whatever the source, a certificate that isn't valid now, or that has no private key when one is
 * required, is refused. The result holds a private key only when one is required.
 *
 * <p>.NET moves a PEM key on Windows out of the ephemeral key it imports as, so SChannel can present
 * it as a TLS server's; JSSE signs with any JDK key, so there is nothing to move and the Java loader
 * doesn't.
 */
public final class CertificateOptionsLoader {
    private static final DateTimeFormatter UNIVERSAL = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss'Z'").withZone(ZoneOffset.UTC);

    /** Opens a KeyStore by its type, loaded; the tests hand in their own stores. */
    @FunctionalInterface
    interface StoreOpener {
        KeyStore open(String type) throws GeneralSecurityException, IOException;
    }

    private final ProtectedReadOnlyCache passwords;
    private final Clock clock;
    private final CertificateOptionsValidator validator;
    private final StoreOpener openStore;

    /** A loader with no password source, judging validity by the system clock: for stores, and files without a password. */
    public CertificateOptionsLoader() {
        this(null, null);
    }

    /**
     * A loader judging validity by the system clock.
     *
     * @param passwords where a file's password is read from, by
     *                  {@link CertificateFileOptions#getPasswordSecretName()} - a FilePerSecretCacheImpl,
     *                  a remote secret cache, systemd credentials; {@code null} when no file has one
     */
    public CertificateOptionsLoader(ProtectedReadOnlyCache passwords) {
        this(passwords, null);
    }

    /**
     * A loader judging validity by the clock given.
     *
     * @param passwords where a file's password is read from; {@code null} when no file has one
     * @param clock     the clock a certificate's validity is judged by; {@code null} for the system's
     */
    public CertificateOptionsLoader(ProtectedReadOnlyCache passwords, Clock clock) {
        this(passwords, clock, new CertificateOptionsValidator(), CertificateOptionsLoader::readStore);
    }

    /** A loader with its validator and store reader given, for tests. */
    CertificateOptionsLoader(ProtectedReadOnlyCache passwords, Clock clock, CertificateOptionsValidator validator, StoreOpener openStore) {
        this.passwords = passwords;
        this.clock = clock == null ? Clock.systemUTC() : clock;
        this.validator = validator;
        this.openStore = openStore;
    }

    /**
     * As {@link #load(CertificateOptions, String)}, for unnamed options.
     *
     * @param options what to open
     * @return the certificate; close it once done
     */
    public LoadedCertificate load(CertificateOptions options) {
        return load(options, null);
    }

    /**
     * Opens the certificate options describes, reading a file's password synchronously - blocking,
     * for a remote password source, until it answers.
     *
     * @param options what to open
     * @param name    the options' name, for named options; it is only reported in a validation failure
     * @return the certificate; close it once done
     * @throws NullPointerException                  {@code options} is null
     * @throws CertificateOptionsValidationException the options aren't valid on this operating system
     * @throws IllegalStateException                 no certificate valid now (with its private key, when
     *                                               required) was found, or a password is needed and
     *                                               the loader has no password source
     * @throws NoSuchElementException                the password source holds no secret by the name given
     * @throws CryptographicException                a file isn't a certificate or key, the password is
     *                                               wrong, or a store couldn't be opened
     * @throws UncheckedIOException                  a file couldn't be read
     */
    public LoadedCertificate load(CertificateOptions options, String name) {
        validator.requireValid(name, options);
        var passwordName = passwordName(options);
        if (passwordName == null)
            return open(options, null);

        var source = passwordSource();
        var maxLength = source.findMaxDecryptedLength(passwordName);
        if (maxLength.isEmpty() || maxLength.getAsInt() == 0)
            throw missingPassword(passwordName);

        var password = new char[maxLength.getAsInt()];
        try {
            var length = source.decrypt(passwordName, password);
            return openWithPassword(options, password, length);
        } finally {
            ArrayUtility.zeroMemory(password);
        }
    }

    /**
     * As {@link #loadAsync(CertificateOptions, String)}, for unnamed options.
     *
     * @param options what to open
     * @return completes with the certificate; close it once done
     */
    public CompletableFuture<LoadedCertificate> loadAsync(CertificateOptions options) {
        return loadAsync(options, null);
    }

    /**
     * As {@link #load(CertificateOptions, String)}, reading a file's password with the password
     * source's asynchronous members, so a remote one blocks no thread. The certificate itself is
     * opened on the thread that completes the password's read, or - with no password to read - on
     * the calling thread, and the future returned already complete.
     *
     * <p>Invalid options throw from the call itself, as argument errors do; every other failure
     * completes the future exceptionally, with the exceptions {@link #load} throws. Cancelling it
     * cancels the password read; the password's buffer is zeroed once that read completes, and a
     * certificate opened after the cancellation is closed.
     *
     * @param options what to open
     * @param name    the options' name, for named options; it is only reported in a validation failure
     * @return completes with the certificate; close it once done
     * @throws NullPointerException                  {@code options} is null
     * @throws CertificateOptionsValidationException the options aren't valid on this operating system
     */
    public CompletableFuture<LoadedCertificate> loadAsync(CertificateOptions options, String name) {
        validator.requireValid(name, options);
        var passwordName = passwordName(options);
        if (passwordName == null) {
            try {
                return CompletableFuture.completedFuture(open(options, null));
            } catch (RuntimeException e) {
                return CompletableFuture.failedFuture(e);
            }
        }

        var result = new CompletableFuture<LoadedCertificate>();
        var pending = new AtomicReference<CompletableFuture<?>>();
        result.whenComplete((loaded, failure) -> {
            var read = pending.get();
            if (result.isCancelled() && read != null)
                read.cancel(false);
        });

        try {
            var source = passwordSource();
            var lengthRead = source.findMaxDecryptedLengthAsync(passwordName);
            pending.set(lengthRead);
            lengthRead.whenComplete((maxLength, lengthFailure) -> {
                if (lengthFailure != null) {
                    result.completeExceptionally(unwrap(lengthFailure));
                    return;
                }
                if (result.isDone())
                    return;
                if (maxLength == null || maxLength.isEmpty() || maxLength.getAsInt() == 0) {
                    result.completeExceptionally(missingPassword(passwordName));
                    return;
                }

                var password = new char[maxLength.getAsInt()];
                CompletableFuture<Integer> decrypt;
                try {
                    decrypt = source.decryptAsync(passwordName, password);
                } catch (RuntimeException e) {
                    ArrayUtility.zeroMemory(password);
                    result.completeExceptionally(e);
                    return;
                }
                pending.set(decrypt);
                if (result.isCancelled())
                    decrypt.cancel(false);
                // A dependent of the read itself, never of result, so it runs - and zeroes - however
                // result completes.
                decrypt.whenComplete((length, decryptFailure) -> {
                    LoadedCertificate loaded = null;
                    Throwable failure = null;
                    try {
                        if (decryptFailure != null)
                            failure = unwrap(decryptFailure);
                        else if (!result.isDone())
                            loaded = openWithPassword(options, password, length);
                    } catch (RuntimeException e) {
                        failure = e;
                    } finally {
                        // Before result completes, so a caller that sees it done never sees the password.
                        ArrayUtility.zeroMemory(password);
                    }
                    if (failure != null)
                        result.completeExceptionally(failure);
                    else if (loaded != null && !result.complete(loaded))
                        loaded.close();
                });
            });
        } catch (RuntimeException e) {
            result.completeExceptionally(e);
        }
        return result;
    }

    // The secret a file's password is in; null when it has none to read. A PKCS#12 file needs its
    // password even for the certificate alone; a PEM certificate without its key needs none.
    private static String passwordName(CertificateOptions options) {
        var file = options.getFile();
        if (file == null)
            return null;
        return file.getFormat() == CertificateFileFormat.PKCS12 || options.isRequirePrivateKey() ? file.getPasswordSecretName() : null;
    }

    private ProtectedReadOnlyCache passwordSource() {
        if (passwords == null)
            throw new IllegalStateException("The certificate's key file has a password, but the loader was given no password source to read it from.");
        return passwords;
    }

    private static NoSuchElementException missingPassword(String passwordName) {
        return new NoSuchElementException("The password source holds no secret named '" + passwordName + "'.");
    }

    private static Throwable unwrap(Throwable failure) {
        return failure instanceof CompletionException && failure.getCause() != null ? failure.getCause() : failure;
    }

    // Opens with the first length chars of password, copied into an exactly sized array zeroed afterwards.
    private LoadedCertificate openWithPassword(CertificateOptions options, char[] password, int length) {
        if (length < 0 || length > password.length)
            throw new IllegalStateException("The password source wrote " + length + " chars into a " + password.length + "-char buffer.");
        var exact = Arrays.copyOf(password, length);
        try {
            return open(options, exact);
        } finally {
            ArrayUtility.zeroMemory(exact);
        }
    }

    // Opens the one source options sets, which validation has made sure of, and checks the result.
    private LoadedCertificate open(CertificateOptions options, char[] password) {
        var require = options.isRequirePrivateKey();
        LoadedCertificate certificate;
        if (options.getWindows() != null)
            certificate = fromStore(StoreTypes.windows(options.getWindows().getStoreLocation(), options.getWindows().getStoreName()), options.getWindows(), require);
        else if (options.getMacOS() != null)
            certificate = fromStore(StoreTypes.macOS(options.getMacOS().getStoreLocation(), options.getMacOS().getStoreName()), options.getMacOS(), require);
        else if (options.getLinux() != null)
            certificate = fromProvider(options.getLinux(), require);
        else
            certificate = fromFile(options.getFile(), require, password);

        try {
            var leaf = certificate.getCertificate();
            if (require && !certificate.hasPrivateKey())
                throw new IllegalStateException("The certificate '" + leaf.getSubjectX500Principal() + "' has no private key.");
            if (!isValidNow(leaf))
                throw new IllegalStateException("The certificate '" + leaf.getSubjectX500Principal() + "' is valid from "
                        + UNIVERSAL.format(leaf.getNotBefore().toInstant()) + " to " + UNIVERSAL.format(leaf.getNotAfter().toInstant()) + ", not now.");
            return certificate;
        } catch (RuntimeException e) {
            certificate.close();
            throw e;
        }
    }

    private record Candidate(String alias, X509Certificate certificate, boolean hasKey) {
    }

    private LoadedCertificate fromStore(String type, CertificateStoreOptions store, boolean requirePrivateKey) {
        if (type == null)
            throw new IllegalStateException("The JDK has no KeyStore for the " + StoreTypes.display(store.getStoreLocation()) + " "
                    + StoreTypes.display(store.getStoreName()) + " store.");
        var subject = new X500Principal(store.getSubject());
        var where = "The " + StoreTypes.display(store.getStoreLocation()) + " " + StoreTypes.display(store.getStoreName()) + " store";
        try {
            var keyStore = openStore.open(type);

            // Compared decoded, as each certificate states its subject, so how either side encodes its
            // strings doesn't matter; ignoring case, as distinguished names compare.
            var named = new ArrayList<Candidate>();
            for (var alias : Collections.list(keyStore.aliases())) {
                if (keyStore.getCertificate(alias) instanceof X509Certificate certificate
                        && DistinguishedNames.sameName(certificate.getSubjectX500Principal(), subject))
                    named.add(new Candidate(alias, certificate, keyStore.isKeyEntry(alias)));
            }
            var chosen = named.stream()
                    .filter(c -> isValidNow(c.certificate()) && (!requirePrivateKey || c.hasKey()))
                    .max(Comparator.comparing(c -> c.certificate().getNotAfter()))
                    .orElse(null);
            if (chosen == null)
                throw new IllegalStateException(named.isEmpty()
                        ? where + " holds no certificate whose subject is '" + store.getSubject() + "'."
                        : where + "'s " + named.size() + " certificate(s) whose subject is '" + store.getSubject() + "' are all "
                                + (requirePrivateKey ? "expired, not yet valid, or without a private key." : "expired or not yet valid."));

            // Only the chosen one's key, and only when it is required: on Windows a handle to the key
            // in CNG or CryptoAPI.
            var key = requirePrivateKey && keyStore.getKey(chosen.alias(), null) instanceof PrivateKey privateKey ? privateKey : null;
            return new LoadedCertificate(chosen.certificate(), chain(keyStore.getCertificateChain(chosen.alias())), key);
        } catch (IOException | GeneralSecurityException e) {
            throw new CryptographicException(where + " couldn't be opened: " + e.getMessage(), e);
        }
    }

    private static LoadedCertificate fromProvider(LinuxOpenSslProviderOptions linux, boolean requirePrivateKey) {
        if (requirePrivateKey)
            throw new UnsupportedOperationException("An OpenSSL provider's key can't be opened from Java.");
        var certificates = certificates(readFile(linux.getCertificateFile()), linux.getCertificateFile());
        return new LoadedCertificate(certificates.get(0), certificates, null);
    }

    private static LoadedCertificate fromFile(CertificateFileOptions file, boolean requirePrivateKey, char[] password) {
        if (file.getFormat() == CertificateFileFormat.PKCS12)
            return fromPkcs12(file.getPath(), requirePrivateKey, password);

        var certificates = certificates(readFile(file.getPath()), file.getPath());
        if (!requirePrivateKey)
            return new LoadedCertificate(certificates.get(0), certificates, null);

        var pem = readFile(file.getKeyPath());
        try {
            var key = PemKeys.read(pem, file.getPasswordSecretName() == null ? null : password, file.getKeyPath());
            if (!PemKeys.matches(key, certificates.get(0).getPublicKey()))
                throw new CryptographicException("The private key in '" + file.getKeyPath() + "' isn't the key of the certificate in '" + file.getPath() + "'.");
            return new LoadedCertificate(certificates.get(0), certificates, key);
        } finally {
            ArrayUtility.zeroMemory(pem);
        }
    }

    // A PKCS#12 file's key entry, else (the key not required) its first certificate. With no password
    // it is opened with an empty one, as .NET opens one.
    private static LoadedCertificate fromPkcs12(String path, boolean requirePrivateKey, char[] password) {
        var contents = readFile(path);
        var pfxPassword = password == null ? new char[0] : password;
        try {
            var keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new ByteArrayInputStream(contents), pfxPassword);

            String chosen = null;
            for (var alias : Collections.list(keyStore.aliases())) {
                if (keyStore.isKeyEntry(alias) && keyStore.getCertificate(alias) instanceof X509Certificate) {
                    chosen = alias;
                    break;
                }
                if (chosen == null && keyStore.getCertificate(alias) instanceof X509Certificate)
                    chosen = alias;
            }
            if (chosen == null)
                throw new CryptographicException("The PKCS#12 file '" + path + "' holds no certificate.");

            var key = requirePrivateKey && keyStore.isKeyEntry(chosen) && keyStore.getKey(chosen, pfxPassword) instanceof PrivateKey privateKey
                    ? privateKey
                    : null;
            var leaf = (X509Certificate) keyStore.getCertificate(chosen);
            return new LoadedCertificate(leaf, chain(keyStore.getCertificateChain(chosen)), key);
        } catch (IOException | GeneralSecurityException e) {
            throw new CryptographicException("The PKCS#12 file '" + path + "' couldn't be opened: its password is wrong, or it isn't PKCS#12.", e);
        } finally {
            ArrayUtility.zeroMemory(contents);
        }
    }

    private static List<X509Certificate> chain(java.security.cert.Certificate[] chain) {
        var certificates = new ArrayList<X509Certificate>();
        if (chain != null) {
            for (var certificate : chain) {
                if (certificate instanceof X509Certificate x509)
                    certificates.add(x509);
            }
        }
        return certificates;
    }

    // Every certificate of a PEM (or DER) file, in order.
    private static List<X509Certificate> certificates(byte[] contents, String path) {
        try {
            var certificates = new ArrayList<X509Certificate>();
            for (var certificate : CertificateFactory.getInstance("X.509").generateCertificates(new ByteArrayInputStream(contents))) {
                if (certificate instanceof X509Certificate x509)
                    certificates.add(x509);
            }
            if (certificates.isEmpty())
                throw new CryptographicException("'" + path + "' holds no certificate.");
            return certificates;
        } catch (CertificateException e) {
            throw new CryptographicException("'" + path + "' isn't a PEM certificate.", e);
        }
    }

    private static byte[] readFile(String path) {
        try {
            return Files.readAllBytes(Path.of(path));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private boolean isValidNow(X509Certificate certificate) {
        var now = clock.instant();
        return !now.isBefore(certificate.getNotBefore().toInstant()) && !now.isAfter(certificate.getNotAfter().toInstant());
    }

    // The operating system's store, loaded. SunMSCAPI and the Apple provider read the store when the
    // KeyStore is loaded, with no stream or password.
    private static KeyStore readStore(String type) throws GeneralSecurityException, IOException {
        var keyStore = KeyStore.getInstance(Objects.requireNonNull(type));
        keyStore.load(null, null);
        return keyStore;
    }
}
