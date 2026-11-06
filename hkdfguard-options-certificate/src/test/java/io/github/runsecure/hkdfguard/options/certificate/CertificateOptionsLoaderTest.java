package io.github.runsecure.hkdfguard.options.certificate;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The loader against real certificates and key files the tests make, and in-memory stores standing in for the operating system's. */
class CertificateOptionsLoaderTest {
    private static final String SUBJECT = "CN=api.example.com, O=Contoso";
    // ASCII: Java 21's PBE key factories, which PKCS12 KeyStore and encrypted PEM keys go through,
    // refuse any other password. aNonAsciiPassword_OpensAPfxAndAPemKey_WhereTheJdkAllowsIt covers the rest.
    private static final String PASSWORD = "passw0rd-123";
    private static final String NON_ASCII_PASSWORD = "pässwörd-123";
    private static final Instant NOW = Instant.parse("2026-11-03T12:00:00Z");

    @TempDir
    Path folder;

    private final FakePasswords passwords = new FakePasswords().with("tls-password", PASSWORD);
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final List<String> opened = new ArrayList<>();

    private static Instant days(int days) {
        return NOW.plus(Duration.ofDays(days));
    }

    private static MemoryKeyStore.Entry entry(int notBeforeDays, int notAfterDays, boolean withKey, String subject) {
        var key = TestCertificates.ec();
        var certificate = TestCertificates.selfSigned(key, subject, days(notBeforeDays), days(notAfterDays));
        return new MemoryKeyStore.Entry(new X509Certificate[] { certificate }, withKey ? key.getPrivate() : null);
    }

    private static MemoryKeyStore.Entry entry(int notBeforeDays, int notAfterDays) {
        return entry(notBeforeDays, notAfterDays, true, SUBJECT);
    }

    private CertificateOptionsLoader loader(Platform platform, MemoryKeyStore store) {
        return new CertificateOptionsLoader(passwords, clock, new CertificateOptionsValidator(platform), type -> {
            opened.add(type);
            return store.keyStore();
        });
    }

    private CertificateOptionsLoader loader(MemoryKeyStore.Entry... entries) {
        return loader(Platform.WINDOWS, MemoryKeyStore.of(entries));
    }

    private static CertificateOptions store(String subject, boolean requirePrivateKey) {
        var store = new CertificateStoreOptions();
        store.setSubject(subject);
        var options = new CertificateOptions();
        options.setWindows(store);
        options.setRequirePrivateKey(requirePrivateKey);
        return options;
    }

    private static CertificateOptions store() {
        return store(SUBJECT, true);
    }

    private static CertificateOptions pfx(String path, String passwordSecretName, boolean allowUnprotected, boolean requirePrivateKey) {
        var file = new CertificateFileOptions();
        file.setPath(path);
        file.setPasswordSecretName(passwordSecretName);
        file.setAllowUnprotectedPrivateKey(allowUnprotected);
        var options = new CertificateOptions();
        options.setFile(file);
        options.setRequirePrivateKey(requirePrivateKey);
        return options;
    }

    private static CertificateOptions pfx(String path) {
        return pfx(path, "tls-password", false, true);
    }

    private static CertificateOptions pem(String path, String keyPath, String passwordSecretName, boolean allowUnprotected) {
        var file = new CertificateFileOptions();
        file.setFormat(CertificateFileFormat.PEM);
        file.setPath(path);
        file.setKeyPath(keyPath);
        file.setPasswordSecretName(passwordSecretName);
        file.setAllowUnprotectedPrivateKey(allowUnprotected);
        var options = new CertificateOptions();
        options.setFile(file);
        return options;
    }

    private String write(String name, byte[] contents) throws IOException {
        var path = folder.resolve(name);
        Files.write(path, contents);
        return path.toString();
    }

    private String write(String name, String contents) throws IOException {
        return write(name, contents.getBytes(StandardCharsets.US_ASCII));
    }

    private static byte[] pkcs12(KeyPair key, X509Certificate certificate, char[] password) throws Exception {
        var keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        if (key != null)
            keyStore.setKeyEntry("tls", key.getPrivate(), password, new X509Certificate[] { certificate });
        else
            keyStore.setCertificateEntry("tls", certificate);
        var out = new ByteArrayOutputStream();
        keyStore.store(out, password);
        return out.toByteArray();
    }

    private static void assertSigns(LoadedCertificate certificate) throws Exception {
        var key = certificate.getPrivateKey();
        assertNotNull(key);
        var algorithm = key.getAlgorithm().equals("RSA") ? "SHA256withRSA" : "SHA256withECDSA";
        var data = "to sign".getBytes(StandardCharsets.US_ASCII);
        var signer = Signature.getInstance(algorithm);
        signer.initSign(key);
        signer.update(data);
        var signature = signer.sign();
        var verifier = Signature.getInstance(algorithm);
        verifier.initVerify(certificate.getCertificate().getPublicKey());
        verifier.update(data);
        assertTrue(verifier.verify(signature));
    }

    private static Throwable failure(CompletableFuture<?> future) {
        var e = assertThrows(CompletionException.class, future::join);
        return e.getCause();
    }

    // --- Stores ----------------------------------------------------------------------------------

    @Test
    void aStore_GivesTheCertificateValidNowWithItsKey_ThatExpiresLast() throws Exception {
        var store = MemoryKeyStore.of(
                entry(-400, -1),                                   // expired
                entry(1, 900),                                     // not yet valid
                entry(-1, 800, false, SUBJECT),                    // newest, without its key
                entry(-200, 100),                                  // older
                entry(-5, 400),                                    // renewed: this one
                entry(-5, 700, true, "CN=other.example.com"));     // another subject

        try (var certificate = loader(Platform.WINDOWS, store).load(store())) {
            assertEquals(List.of("Windows-MY-LOCALMACHINE"), opened);
            assertEquals(days(400).getEpochSecond(), certificate.getCertificate().getNotAfter().toInstant().getEpochSecond());
            assertTrue(certificate.hasPrivateKey());
            assertSigns(certificate);
            // Only the chosen certificate's key was asked of the store.
            assertEquals(List.of("entry-4"), store.keysRequested);
        }
    }

    @Test
    void aStore_WithoutAKeyRequired_GivesTheNewestValidOne_AndNoKey() throws Exception {
        var store = MemoryKeyStore.of(entry(-200, 100), entry(-1, 800, false, SUBJECT));
        var loader = loader(Platform.WINDOWS, store);

        try (var certificate = loader.load(store(SUBJECT, false)); var loadedAsync = loader.loadAsync(store(SUBJECT, false)).join()) {
            assertFalse(certificate.hasPrivateKey());
            assertEquals(days(800).getEpochSecond(), certificate.getCertificate().getNotAfter().toInstant().getEpochSecond());
            assertEquals(certificate.getCertificate(), loadedAsync.getCertificate());
            assertTrue(store.keysRequested.isEmpty());
        }
    }

    @Test
    void aStoresSubject_IsComparedWhole_IgnoringCase() {
        try (var certificate = loader(entry(-1, 100)).load(store("cn=API.example.com, o=contoso", true))) {
            assertEquals(SUBJECT, certificate.getCertificate().getSubjectX500Principal().toString());
        }

        var ex = assertThrows(IllegalStateException.class, () -> loader(entry(-1, 100)).load(store("CN=api.example.com", true)));
        assertTrue(ex.getMessage().contains("holds no certificate whose subject is"));
    }

    @Test
    void aStoreWithoutACertificateToGive_SaysWhy() {
        var none = assertThrows(IllegalStateException.class, () -> loader(entry(-1, 100, true, "CN=other")).load(store()));
        assertEquals("The LocalMachine My store holds no certificate whose subject is '" + SUBJECT + "'.", none.getMessage());

        var unusable = assertThrows(IllegalStateException.class, () -> loader(entry(-400, -1), entry(-1, 100, false, SUBJECT)).load(store()));
        assertTrue(unusable.getMessage().contains("2 certificate(s)"), unusable.getMessage());
        assertTrue(unusable.getMessage().contains("without a private key"), unusable.getMessage());

        var expired = assertThrows(IllegalStateException.class, () -> loader(entry(-400, -1)).load(store(SUBJECT, false)));
        assertTrue(expired.getMessage().endsWith("expired or not yet valid."), expired.getMessage());
    }

    @Test
    void eachWindowsStore_OpensItsSunMscapiKeyStore() {
        var options = store();
        var expected = List.of("Windows-MY-CURRENTUSER", "Windows-ROOT-CURRENTUSER", "Windows-MY-LOCALMACHINE", "Windows-ROOT-LOCALMACHINE");
        for (var location : StoreLocation.values()) {
            for (var name : List.of(StoreName.MY, StoreName.ROOT)) {
                options.getWindows().setStoreLocation(location);
                options.getWindows().setStoreName(name);
                loader(entry(-1, 100)).load(options).close();
            }
        }
        assertEquals(expected, opened);
    }

    @Test
    void aMacOSKeychain_IsReadAsAStore_WithoutItsKey() {
        var macOS = new CertificateStoreOptions();
        macOS.setStoreLocation(StoreLocation.CURRENT_USER);
        macOS.setSubject(SUBJECT);
        var options = new CertificateOptions();
        options.setMacOS(macOS);
        options.setRequirePrivateKey(false);
        var store = MemoryKeyStore.of(entry(-1, 100));

        try (var certificate = loader(Platform.MACOS, store).load(options)) {
            assertFalse(certificate.hasPrivateKey());
        }
        macOS.setStoreLocation(StoreLocation.LOCAL_MACHINE);
        macOS.setStoreName(StoreName.ROOT);
        loader(Platform.MACOS, store).load(options).close();

        assertEquals(List.of("KeychainStore", "KeychainStore-ROOT"), opened);
        // The keychain's export of a key is never asked for.
        assertTrue(store.keysRequested.isEmpty());
    }

    @Test
    void aStoresChain_IsKept() {
        var key = TestCertificates.ec();
        var leaf = TestCertificates.selfSigned(key, SUBJECT, days(-1), days(100));
        var issuer = TestCertificates.selfSigned(TestCertificates.ec(), "CN=Contoso Root", days(-1), days(1000));
        var loader = loader(new MemoryKeyStore.Entry(new X509Certificate[] { leaf, issuer }, key.getPrivate()));

        try (var certificate = loader.load(store())) {
            assertEquals(List.of(leaf, issuer), certificate.getCertificateChain());
        }
    }

    @Test
    void aStoreThatCantBeOpened_IsACryptographicException() {
        var loader = new CertificateOptionsLoader(passwords, clock, new CertificateOptionsValidator(Platform.WINDOWS), type -> {
            throw new java.security.KeyStoreException("no such store");
        });

        var ex = assertThrows(CryptographicException.class, () -> loader.load(store()));
        assertEquals("The LocalMachine My store couldn't be opened: no such store", ex.getMessage());
    }

    // --- PKCS#12 ---------------------------------------------------------------------------------

    @Test
    void aPfx_IsOpenedWithItsPassword_FromThePasswordSource() throws Exception {
        var key = TestCertificates.rsa();
        var original = TestCertificates.selfSigned(key, SUBJECT, days(-10), days(300));
        var path = write("tls.pfx", pkcs12(key, original, PASSWORD.toCharArray()));
        var loader = loader();

        try (var loaded = loader.load(pfx(path)); var loadedAsync = loader.loadAsync(pfx(path)).join()) {
            assertEquals(original, loaded.getCertificate());
            assertSigns(loaded);
            assertSigns(loadedAsync);
            assertEquals(1, passwords.reads);
            assertEquals(1, passwords.asyncReads);
        }
    }

    @Test
    void thePassword_IsZeroed_OnceTheKeyIsRead() throws Exception {
        var key = TestCertificates.ec();
        var path = write("tls.pfx", pkcs12(key, TestCertificates.selfSigned(key, SUBJECT, days(-10), days(300)), PASSWORD.toCharArray()));

        loader().load(pfx(path)).close();
        loader().loadAsync(pfx(path)).join().close();

        assertEquals(2, passwords.buffers.size());
        for (var buffer : passwords.buffers)
            assertTrue(ArrayUtility.isNullOrEmpty(buffer));
    }

    @Test
    void aWrongPassword_IsRefused() throws Exception {
        var key = TestCertificates.ec();
        var path = write("tls.pfx", pkcs12(key, TestCertificates.selfSigned(key, SUBJECT, days(-10), days(300)), "another password".toCharArray()));

        assertThrows(CryptographicException.class, () -> loader().load(pfx(path)));
        assertInstanceOf(CryptographicException.class, failure(loader().loadAsync(pfx(path))));
        for (var buffer : passwords.buffers)
            assertTrue(ArrayUtility.isNullOrEmpty(buffer));
    }

    @Test
    void aMissingPassword_OrNoPasswordSource_IsRefused() throws Exception {
        var key = TestCertificates.ec();
        var path = write("tls.pfx", pkcs12(key, TestCertificates.selfSigned(key, SUBJECT, days(-10), days(300)), PASSWORD.toCharArray()));

        var missing = assertThrows(NoSuchElementException.class, () -> loader().load(pfx(path, "absent", false, true)));
        assertEquals("The password source holds no secret named 'absent'.", missing.getMessage());
        assertInstanceOf(NoSuchElementException.class, failure(loader().loadAsync(pfx(path, "absent", false, true))));

        var noSource = new CertificateOptionsLoader(null, clock);
        assertThrows(IllegalStateException.class, () -> noSource.load(pfx(path)));
        assertInstanceOf(IllegalStateException.class, failure(noSource.loadAsync(pfx(path))));
    }

    @Test
    void anUnprotectedPfx_IsOpened_WhenAllowed() throws Exception {
        var key = TestCertificates.ec();
        var path = write("tls.pfx", pkcs12(key, TestCertificates.selfSigned(key, SUBJECT, days(-10), days(300)), new char[0]));
        var loader = new CertificateOptionsLoader(null, clock);

        try (var loaded = loader.load(pfx(path, null, true, true)); var loadedAsync = loader.loadAsync(pfx(path, null, true, true)).join()) {
            assertSigns(loaded);
            assertSigns(loadedAsync);
        }
    }

    @Test
    void aPfx_NeedsItsPassword_EvenForTheCertificateAlone() throws Exception {
        var key = TestCertificates.ec();
        var original = TestCertificates.selfSigned(key, SUBJECT, days(-10), days(300));
        var path = write("tls.pfx", pkcs12(key, original, PASSWORD.toCharArray()));

        try (var loaded = loader().load(pfx(path, "tls-password", false, false))) {
            assertEquals(original, loaded.getCertificate());
            assertFalse(loaded.hasPrivateKey());
            assertEquals(1, passwords.reads);
        }
    }

    // --- PEM -------------------------------------------------------------------------------------

    @Test
    void aPemCertificate_WithAnEncryptedKey_IsOpenedWithItsPassword_UnderPbes2AndPkcs12Schemes() throws Exception {
        var cases = List.of(
                new Object[] { TestCertificates.rsa(), "PBEWithHmacSHA256AndAES_256" },
                new Object[] { TestCertificates.ec(), "PBEWithHmacSHA256AndAES_256" },
                new Object[] { TestCertificates.ec(), "PBEWithHmacSHA1AndAES_128" },
                new Object[] { TestCertificates.ec(), "PBEWithHmacSHA512AndAES_256" },
                new Object[] { TestCertificates.ec(), "PBEWithSHA1AndDESede" });
        var i = 0;
        for (var c : cases) {
            var key = (KeyPair) c[0];
            var scheme = (String) c[1];
            var original = TestCertificates.selfSigned(key, SUBJECT, days(-10), days(300));
            var keyPem = scheme.startsWith("PBEWithHmac")
                    ? TestCertificates.encryptedPbes2Pem(key.getPrivate(), PASSWORD.toCharArray(), scheme, 100_000)
                    : TestCertificates.encryptedPbes1Pem(key.getPrivate(), PASSWORD.toCharArray(), scheme);
            var options = pem(write("tls" + i + ".crt", TestCertificates.certificatePem(original)), write("tls" + i + ".key", keyPem), "tls-password", false);
            i++;

            try (var loaded = loader().load(options); var loadedAsync = loader().loadAsync(options).join()) {
                assertEquals(original, loaded.getCertificate(), scheme);
                assertSigns(loaded);
                assertSigns(loadedAsync);
            }
        }
    }

    @Test
    void aNonAsciiPassword_OpensAPfxAndAPemKey_WhereTheJdkAllowsIt() throws Exception {
        assumeTrue(jdkAcceptsNonAsciiPbePasswords(), "This JDK's PBE key factories take ASCII passwords only (Java 21 does).");
        passwords.with("tls-password-utf8", NON_ASCII_PASSWORD);
        var key = TestCertificates.ec();
        var original = TestCertificates.selfSigned(key, SUBJECT, days(-10), days(300));
        var pfxPath = write("tls.pfx", pkcs12(key, original, NON_ASCII_PASSWORD.toCharArray()));
        var keyPem = TestCertificates.encryptedPbes2Pem(key.getPrivate(), NON_ASCII_PASSWORD.toCharArray(), "PBEWithHmacSHA256AndAES_256", 1000);
        var pemOptions = pem(write("tls.crt", TestCertificates.certificatePem(original)), write("tls.key", keyPem), "tls-password-utf8", false);

        for (var options : List.of(pfx(pfxPath, "tls-password-utf8", false, true), pemOptions)) {
            try (var loaded = loader().load(options)) {
                assertEquals(original, loaded.getCertificate());
                assertSigns(loaded);
            }
        }
    }

    private static boolean jdkAcceptsNonAsciiPbePasswords() {
        try {
            SecretKeyFactory.getInstance("PBEWithHmacSHA256AndAES_256").generateSecret(new PBEKeySpec(NON_ASCII_PASSWORD.toCharArray()));
            return true;
        } catch (java.security.GeneralSecurityException e) {
            return false;
        }
    }

    @Test
    void aPemFile_GivesEveryCertificateInIt_AsTheChain() throws Exception {
        var key = TestCertificates.ec();
        var leaf = TestCertificates.selfSigned(key, SUBJECT, days(-10), days(300));
        var issuer = TestCertificates.selfSigned(TestCertificates.ec(), "CN=Contoso CA", days(-10), days(900));
        var options = pem(write("chain.crt", TestCertificates.certificatePem(leaf, issuer)),
                write("tls.key", TestCertificates.encryptedPbes2Pem(key.getPrivate(), PASSWORD.toCharArray(), "PBEWithHmacSHA256AndAES_256", 1000)),
                "tls-password", false);

        try (var loaded = loader().load(options)) {
            assertEquals(leaf, loaded.getCertificate());
            assertEquals(List.of(leaf, issuer), loaded.getCertificateChain());
        }
    }

    @Test
    void aPemCertificate_WithAPlainKey_IsOpened_WhenAllowed() throws Exception {
        var key = TestCertificates.rsa();
        var original = TestCertificates.selfSigned(key, SUBJECT, days(-10), days(300));
        var options = pem(write("tls.crt", TestCertificates.certificatePem(original)),
                write("tls.key", TestCertificates.pem("PRIVATE KEY", key.getPrivate().getEncoded())), null, true);

        try (var loaded = new CertificateOptionsLoader(null, clock).load(options)) {
            assertSigns(loaded);
        }
    }

    @Test
    void aPemKey_OfTheWrongKind_IsRefused_SayingWhy() throws Exception {
        var key = TestCertificates.ec();
        var certificate = write("tls.crt", TestCertificates.certificatePem(TestCertificates.selfSigned(key, SUBJECT, days(-10), days(300))));
        var encrypted = write("encrypted.key", TestCertificates.encryptedPbes2Pem(key.getPrivate(), PASSWORD.toCharArray(), "PBEWithHmacSHA256AndAES_256", 1000));
        var plain = write("plain.key", TestCertificates.pem("PRIVATE KEY", key.getPrivate().getEncoded()));
        var pkcs1 = write("pkcs1.key", TestCertificates.pem("RSA PRIVATE KEY", new byte[] { 0x30, 0x00 }));
        var another = write("another.key", TestCertificates.pem("PRIVATE KEY", TestCertificates.ec().getPrivate().getEncoded()));

        var ex = assertThrows(CryptographicException.class, () -> loader().load(pem(certificate, encrypted, null, true)));
        assertTrue(ex.getMessage().contains("is encrypted, but no File.PasswordSecretName"), ex.getMessage());

        ex = assertThrows(CryptographicException.class, () -> loader().load(pem(certificate, plain, "tls-password", false)));
        assertTrue(ex.getMessage().contains("isn't encrypted, but File.PasswordSecretName names a password"), ex.getMessage());

        ex = assertThrows(CryptographicException.class, () -> loader().load(pem(certificate, pkcs1, null, true)));
        assertTrue(ex.getMessage().contains("holds no PEM \"PRIVATE KEY\" block"), ex.getMessage());

        ex = assertThrows(CryptographicException.class, () -> loader().load(pem(certificate, another, null, true)));
        assertTrue(ex.getMessage().contains("isn't the key of the certificate"), ex.getMessage());

        passwords.with("wrong", "not the password");
        ex = assertThrows(CryptographicException.class, () -> loader().load(pem(certificate, encrypted, "wrong", false)));
        assertTrue(ex.getMessage().contains("password is wrong"), ex.getMessage());
    }

    @Test
    void aPemCertificate_Alone_NeedsNoKeyOrPassword() throws Exception {
        var key = TestCertificates.ec();
        var options = pem(write("ca.crt", TestCertificates.certificatePem(TestCertificates.selfSigned(key, SUBJECT, days(-10), days(300)))), null,
                "tls-password", false);
        options.setRequirePrivateKey(false);

        try (var loaded = loader().load(options)) {
            assertFalse(loaded.hasPrivateKey());
            assertEquals(0, passwords.reads);
        }
    }

    @Test
    void aFileCertificate_NotValidNow_OrWithoutItsKey_IsRefused() throws Exception {
        var key = TestCertificates.ec();
        var expired = write("expired.pfx", pkcs12(key, TestCertificates.selfSigned(key, SUBJECT, days(-400), days(-1)), new char[0]));
        var keyless = write("keyless.pfx", pkcs12(null, TestCertificates.selfSigned(key, SUBJECT, days(-1), days(100)), new char[0]));

        var ex = assertThrows(IllegalStateException.class, () -> loader().load(pfx(expired, null, true, true)));
        assertEquals("The certificate '" + SUBJECT + "' is valid from 2025-09-29 12:00:00Z to 2026-11-02 12:00:00Z, not now.", ex.getMessage());
        ex = assertThrows(IllegalStateException.class, () -> loader().load(pfx(keyless, null, true, true)));
        assertTrue(ex.getMessage().contains("has no private key"), ex.getMessage());
    }

    @Test
    void aMissingFile_IsAnUncheckedIOException() {
        assertThrows(UncheckedIOException.class, () -> loader().load(pfx(folder.resolve("absent.pfx").toString(), null, true, true)));
    }

    @Test
    void aLinuxCertificate_IsReadFromItsFile_ItsProviderKeyNever() throws Exception {
        var key = TestCertificates.ec();
        var original = TestCertificates.selfSigned(key, SUBJECT, days(-10), days(300));
        var path = write("tls.crt", TestCertificates.certificatePem(original));
        var linux = new LinuxOpenSslProviderOptions();
        linux.setCertificateFile(path);
        var options = new CertificateOptions();
        options.setLinux(linux);
        options.setRequirePrivateKey(false);

        try (var alone = loader(Platform.LINUX, MemoryKeyStore.of()).load(options)) {
            assertEquals(original, alone.getCertificate());
        }

        // Validation refuses the key on Linux; a loader validating for nothing still won't open it.
        linux.setKeyUri("handle:0x81000001");
        options.setRequirePrivateKey(true);
        assertThrows(CertificateOptionsValidationException.class, () -> loader(Platform.LINUX, MemoryKeyStore.of()).load(options));
    }

    // --- Validation and async --------------------------------------------------------------------

    @Test
    void invalidOptions_AreRefused_BeforeAnythingIsOpened() {
        var ex = assertThrows(CertificateOptionsValidationException.class, () -> loader().load(new CertificateOptions(), "tls"));
        assertEquals("tls", ex.getOptionsName());
        assertTrue(ex.getMessage().startsWith("Certificate options 'tls' are invalid: One certificate source is required"), ex.getMessage());

        var unnamed = assertThrows(CertificateOptionsValidationException.class, () -> loader().loadAsync(new CertificateOptions()));
        assertEquals("", unnamed.getOptionsName());

        assertThrows(NullPointerException.class, () -> loader().load(null));
        assertThrows(NullPointerException.class, () -> loader().loadAsync(null));
        assertTrue(opened.isEmpty());
    }

    @Test
    void cancellingLoadAsync_ZeroesThePassword_OnceItsReadCompletes_AndOpensNothing() throws Exception {
        var key = TestCertificates.ec();
        var path = write("tls.pfx", pkcs12(key, TestCertificates.selfSigned(key, SUBJECT, days(-10), days(300)), PASSWORD.toCharArray()));
        passwords.pendingDecrypt = new CompletableFuture<>();

        var loading = loader().loadAsync(pfx(path));
        assertFalse(ArrayUtility.isNullOrEmpty(passwords.buffers.get(0)));
        assertTrue(loading.cancel(false));

        // The cancellation reached the password read, and its completion zeroed the buffer.
        assertTrue(passwords.pendingDecrypt.isCancelled());
        assertTrue(ArrayUtility.isNullOrEmpty(passwords.buffers.get(0)));
    }

    @Test
    void aPasswordReadThatFails_FailsTheLoad_AndZeroesTheBuffer() throws Exception {
        var key = TestCertificates.ec();
        var path = write("tls.pfx", pkcs12(key, TestCertificates.selfSigned(key, SUBJECT, days(-10), days(300)), PASSWORD.toCharArray()));
        passwords.pendingDecrypt = new CompletableFuture<>();

        var loading = loader().loadAsync(pfx(path));
        passwords.pendingDecrypt.completeExceptionally(new IllegalStateException("the vault is sealed"));

        assertEquals("the vault is sealed", failure(loading).getMessage());
        assertTrue(ArrayUtility.isNullOrEmpty(passwords.buffers.get(0)));
    }

    @Test
    void thePublicConstructors_ValidateForThisOperatingSystem() throws Exception {
        var key = TestCertificates.ec();
        // A real certificate: the system clock judges it valid now.
        var path = write("tls.pfx", pkcs12(key, TestCertificates.selfSigned(key, SUBJECT, Instant.now().minusSeconds(60), Instant.now().plusSeconds(3600)),
                PASSWORD.toCharArray()));
        try (var loaded = new CertificateOptionsLoader(passwords).load(pfx(path))) {
            assertTrue(loaded.hasPrivateKey());
        }
        assertThrows(IllegalStateException.class, () -> new CertificateOptionsLoader().load(pfx(path)));
        assertThrows(IllegalStateException.class, () -> new CertificateOptionsLoader(null, null).load(pfx(path, "tls-password", false, false)));
    }

    @Test
    void aSoftwareKey_IsAJdkKey_NotAStoreHandle() throws Exception {
        var key = TestCertificates.ec();
        var path = write("tls.pfx", pkcs12(key, TestCertificates.selfSigned(key, SUBJECT, days(-10), days(300)), PASSWORD.toCharArray()));
        try (var loaded = loader().load(pfx(path))) {
            PrivateKey loadedKey = loaded.getPrivateKey();
            assertArrayEquals(key.getPrivate().getEncoded(), loadedKey.getEncoded());
        }
    }

    private CertificateOptionsLoader loader() {
        return loader(Platform.WINDOWS, MemoryKeyStore.of());
    }
}
