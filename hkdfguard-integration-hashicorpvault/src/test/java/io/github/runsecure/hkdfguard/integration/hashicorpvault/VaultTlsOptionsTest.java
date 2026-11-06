package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import static io.github.runsecure.hkdfguard.integration.hashicorpvault.Futures.assertFailsWith;
import static io.github.runsecure.hkdfguard.integration.hashicorpvault.Futures.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.Test;

/** The client's TLS against a real https fake Vault, with certificates keytool made. */
class VaultTlsOptionsTest {
    private static final TlsMaterials TLS = TlsMaterials.get();

    private static VaultClient client(FakeVault vault, VaultTlsOptions tls) {
        return client(vault, tls, b -> {
        });
    }

    private static VaultClient client(FakeVault vault, VaultTlsOptions tls, java.util.function.Consumer<VaultClientOptions.Builder> configure) {
        var protector = TestRings.protector();
        var options = VaultClientOptions.builder()
                .address(vault.address())
                .tls(tls)
                .token(StaticVaultToken.protect(protector, FakeVault.TOKEN))
                .retry(VaultRetryOptions.builder().retryWaitMin(Duration.ZERO).retryWaitMax(Duration.ZERO).build());
        configure.accept(options);
        return new VaultClient(protector, options.build());
    }

    // The failure the future ends with, or null if it succeeded.
    private static Throwable failure(CompletableFuture<?> future) {
        try {
            future.get(20, TimeUnit.SECONDS);
            return null;
        } catch (ExecutionException e) {
            return e.getCause();
        } catch (Exception e) {
            throw new AssertionError(e);
        }
    }

    private static boolean isHandshakeFailure(Throwable failure) {
        for (var e = failure; e != null; e = e.getCause()) {
            if (e instanceof SSLHandshakeException)
                return true;
        }
        return false;
    }

    @Test
    void theDefaultTrust_RefusesAPrivateCa_WithoutRetrying() {
        try (var vault = new FakeVault(TLS.serverContext(TLS.serverForHostAndIp, false));
                var client = client(vault, VaultTlsOptions.builder().build())) {
            var failure = assertFailsWith(IOException.class, client.readAsync("a"));

            assertTrue(isHandshakeFailure(failure), String.valueOf(failure));
            assertTrue(vault.requests().isEmpty());
        }
    }

    @Test
    void aCaCertificate_IsTrusted_ForCertificatesItSigned_AndOnlyThose() {
        var trusted = VaultTlsOptions.builder().serverCertificatePem(TLS.caPem.getBytes(StandardCharsets.US_ASCII)).build();
        try (var vault = new FakeVault(TLS.serverContext(TLS.serverForHostAndIp, false)); var client = client(vault, trusted)) {
            await(client.readAsync("a"));
            assertEquals(FakeVault.TOKEN, vault.single().header("X-Vault-Token"));
        }
        try (var vault = new FakeVault(TLS.serverContext(TLS.serverSelfSigned, false)); var client = client(vault, trusted)) {
            assertTrue(isHandshakeFailure(failure(client.readAsync("a"))));
        }
    }

    @Test
    void caCertificates_ComeFromAFile_OrADirectory_FileFirst() throws IOException {
        var directory = Files.createTempDirectory(TLS.directory, "capath");
        Files.writeString(directory.resolve("a.pem"), TlsMaterials.pem("CERTIFICATE", selfSignedEncoded()));
        Files.writeString(directory.resolve("b.pem"), TLS.caPem);
        var garbage = TLS.write("garbage.pem", "not a certificate");

        try (var vault = new FakeVault(TLS.serverContext(TLS.serverForHostAndIp, false))) {
            try (var client = client(vault, VaultTlsOptions.builder().serverCertificateFile(TLS.directory.resolve("ca.pem"))
                    .serverCertificateDirectory(Path.of("does-not-exist")).build())) {
                await(client.readAsync("a"));
            }
            try (var client = client(vault, VaultTlsOptions.builder().serverCertificateDirectory(directory).build())) {
                await(client.readAsync("b"));
            }
        }
        assertThrows(IllegalArgumentException.class, () -> VaultTlsOptions.builder().serverCertificateFile(garbage).build().createSslContext());
        assertThrows(IllegalArgumentException.class,
                () -> VaultTlsOptions.builder().serverCertificateFile(TLS.directory.resolve("missing.pem")).build().createSslContext());
        Files.writeString(directory.resolve("c.txt"), "no certificate here");
        assertThrows(IllegalArgumentException.class, () -> VaultTlsOptions.builder().serverCertificateDirectory(directory).build().createSslContext());
    }

    private static byte[] selfSignedEncoded() {
        try {
            return TLS.serverSelfSigned.getEncoded();
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new AssertionError(e);
        }
    }

    @Test
    void aCaPemWithoutACertificate_IsRefused_WhenTheClientIsCreated() {
        try (var vault = new FakeVault()) {
            var e = assertThrows(IllegalArgumentException.class, () -> client(vault,
                    VaultTlsOptions.builder().serverCertificatePem("-----BEGIN NOTHING-----\nAAAA\n-----END NOTHING-----\n".getBytes(StandardCharsets.US_ASCII)).build()));
            assertTrue(e.getMessage().contains("no PEM-encoded certificate"), e.getMessage());
        }
    }

    @Test
    void serverName_ReplacesTheHostTheCertificateMustName() {
        var ca = TLS.caPem.getBytes(StandardCharsets.US_ASCII);
        try (var vault = new FakeVault(TLS.serverContext(TLS.serverForNameOnly, false))) {
            try (var client = client(vault, VaultTlsOptions.builder().serverCertificatePem(ca).build())) {
                assertTrue(isHandshakeFailure(failure(client.readAsync("a"))));
            }
            try (var client = client(vault, VaultTlsOptions.builder().serverCertificatePem(ca).serverName("VAULT.test.").build())) {
                await(client.readAsync("a"));
            }
            try (var client = client(vault, VaultTlsOptions.builder().serverCertificatePem(ca).serverName("other.test").build())) {
                assertTrue(isHandshakeFailure(failure(client.readAsync("a"))));
            }
            assertEquals(1, vault.requests().size());
        }
    }

    @Test
    void serverName_UsesTheSystemTrust_WithoutACa() {
        try (var vault = new FakeVault(TLS.serverContext(TLS.serverForNameOnly, false));
                var client = client(vault, VaultTlsOptions.builder().serverName("vault.test").build())) {
            assertTrue(isHandshakeFailure(failure(client.readAsync("a"))));
        }
    }

    @Test
    void insecureSkipVerify_AcceptsAnything() {
        try (var vault = new FakeVault(TLS.serverContext(TLS.serverForNameOnly, false));
                var client = client(vault, VaultTlsOptions.builder().insecureSkipVerify(true).build())) {
            await(client.readAsync("a"));
        }
    }

    @Test
    void aRedirectFromHttpsToHttp_IsADowngrade() {
        try (var vault = new FakeVault(TLS.serverContext(TLS.serverForHostAndIp, false));
                var client = client(vault, VaultTlsOptions.builder().serverCertificatePem(TLS.caPem.getBytes(StandardCharsets.US_ASCII)).build(),
                        b -> b.followRedirects(true))) {
            vault.then(307, "", "Location", "http://127.0.0.1:" + vault.address().getPort() + "/v1/b");

            var e = assertFailsWith(VaultRedirectException.class, client.readAsync("a"));

            assertEquals("the redirect would cause a protocol downgrade", e.reason());
            assertEquals(1, vault.requests().size());
        }
    }

    @Test
    void aClientCertificate_IsPresented_WhateverCasVaultAsksFor() {
        var ca = TLS.caPem.getBytes(StandardCharsets.US_ASCII);
        var certificate = pem(TLS.client);
        try (var vault = new FakeVault(TLS.serverContext(TLS.serverForHostAndIp, true), true)) {
            try (var client = client(vault, VaultTlsOptions.builder().serverCertificatePem(ca).build())) {
                var noCertificate = failure(client.readAsync("a"));
                assertTrue(noCertificate instanceof IOException, String.valueOf(noCertificate));
            }
            try (var client = client(vault, VaultTlsOptions.builder().serverCertificatePem(ca).clientCertificatePem(certificate)
                    .clientCertificateKeyPem(TlsMaterials.pem("PRIVATE KEY", TLS.clientKey.getEncoded()).getBytes(StandardCharsets.US_ASCII)).build())) {
                await(client.readAsync("pkcs8"));
            }
            try (var client = client(vault, VaultTlsOptions.builder().serverCertificatePem(ca).clientCertificatePem(certificate)
                    .clientCertificateKeyPem(TlsMaterials.pem("RSA PRIVATE KEY", TlsMaterials.pkcs1(TLS.clientKey)).getBytes(StandardCharsets.US_ASCII)).build())) {
                await(client.readAsync("pkcs1"));
            }
            // The server's own EC certificate is issued for client authentication too: a SEC1 key.
            var certificateFile = TLS.write("ec-client.pem", new String(pem(TLS.serverForHostAndIp), StandardCharsets.US_ASCII));
            var keyFile = TLS.write("ec-client.key", TlsMaterials.pem("EC PRIVATE KEY", TlsMaterials.sec1WithCurve(TLS.serverKey)));
            try (var client = client(vault, VaultTlsOptions.builder().serverCertificatePem(ca).clientCertificateFile(certificateFile)
                    .clientCertificateKeyFile(keyFile).build())) {
                await(client.readAsync("sec1"));
            }
            assertEquals(3, vault.requests().size());
            assertEquals(java.util.List.of("CN=hkdfguard-client", "CN=hkdfguard-client", "CN=vault.test"), vault.clientCertificates);
        }
    }

    @Test
    void aClientCertificate_NeedsItsKey_AndViceVersa_AndBothMustRead() {
        var certificate = pem(TLS.client);
        var key = TlsMaterials.pem("PRIVATE KEY", TLS.clientKey.getEncoded()).getBytes(StandardCharsets.US_ASCII);

        assertThrows(IllegalArgumentException.class, () -> VaultTlsOptions.builder().clientCertificatePem(certificate).build().createSslContext());
        assertThrows(IllegalArgumentException.class, () -> VaultTlsOptions.builder().clientCertificateKeyPem(key).build().createSslContext());
        assertThrows(IllegalArgumentException.class, () -> VaultTlsOptions.builder().clientCertificatePem("junk".getBytes(StandardCharsets.US_ASCII))
                .clientCertificateKeyPem(key).build().createSslContext());
        assertThrows(IllegalArgumentException.class, () -> VaultTlsOptions.builder().clientCertificatePem(certificate)
                .clientCertificateKeyPem("junk".getBytes(StandardCharsets.US_ASCII)).build().createSslContext());
        var encrypted = assertThrows(IllegalArgumentException.class, () -> VaultTlsOptions.builder().clientCertificatePem(certificate)
                .clientCertificateKeyPem(TlsMaterials.pem("ENCRYPTED PRIVATE KEY", new byte[] {1, 2, 3}).getBytes(StandardCharsets.US_ASCII)).build()
                .createSslContext());
        assertTrue(encrypted.getMessage().contains("encrypted"), encrypted.getMessage());
        var noCurve = TlsMaterials.Der.tlv(0x30, concat(new byte[] {2, 1, 1}, TlsMaterials.Der.tlv(0x04, new byte[32])));
        assertThrows(IllegalArgumentException.class, () -> VaultTlsOptions.builder().clientCertificatePem(certificate)
                .clientCertificateKeyPem(TlsMaterials.pem("EC PRIVATE KEY", noCurve).getBytes(StandardCharsets.US_ASCII)).build().createSslContext());
        VaultTlsOptions.builder().clientCertificatePem(certificate).clientCertificateKeyPem(key).build().createSslContext();
    }

    @Test
    void matchesHostname_IsGoVerifyHostname() {
        var cert = TLS.serverForHostAndIp;
        assertTrue(VaultTlsOptions.matchesHostname(cert, "vault.test"));
        assertTrue(VaultTlsOptions.matchesHostname(cert, "VAULT.TEST."));
        assertTrue(VaultTlsOptions.matchesHostname(cert, "127.0.0.1"));
        assertFalse(VaultTlsOptions.matchesHostname(cert, "127.0.0.2"));
        assertFalse(VaultTlsOptions.matchesHostname(cert, "sub.vault.test"));
        assertFalse(VaultTlsOptions.matchesHostname(TLS.serverForNameOnly, "127.0.0.1"));
        // The CA has no alternative names, and its common name doesn't count.
        assertFalse(VaultTlsOptions.matchesHostname(TLS.ca, "HkdfGuard Test CA"));
        assertFalse(VaultTlsOptions.matchesHostname(TLS.serverSelfSigned, "vault.test"));
    }

    private static byte[] pem(java.security.cert.X509Certificate certificate) {
        try {
            return TlsMaterials.pem("CERTIFICATE", certificate.getEncoded()).getBytes(StandardCharsets.US_ASCII);
        } catch (java.security.cert.CertificateEncodingException e) {
            throw new AssertionError(e);
        }
    }

    private static byte[] concat(byte[] a, byte[] b) {
        var all = new byte[a.length + b.length];
        System.arraycopy(a, 0, all, 0, a.length);
        System.arraycopy(b, 0, all, a.length, b.length);
        return all;
    }

    @Test
    void anAddressIsReachedByIp_TheTlsHandshakeNamingIt() {
        // The certificate is issued to 127.0.0.1 too, so the JDK's own name check passes without serverName.
        try (var vault = new FakeVault(TLS.serverContext(TLS.serverForHostAndIp, false));
                var client = client(vault, VaultTlsOptions.builder().serverCertificatePem(TLS.caPem.getBytes(StandardCharsets.US_ASCII)).build())) {
            assertEquals(URI.create("https://127.0.0.1:" + vault.address().getPort()), vault.address());
            await(client.readAsync("a"));
            assertFalse(vault.requests().isEmpty());
        }
    }

    private static final char[] STORE_PASSWORD = "store-secret".toCharArray();

    private static Passwords passwords() {
        var protector = TestRings.ring().createProtector(VaultTlsOptions.PASSWORD_PURPOSE);
        return new Passwords(protector, VaultTlsOptions.protectPassword(protector, STORE_PASSWORD));
    }

    private record Passwords(io.github.runsecure.hkdfguard.abstractions.DataProtector protector, String password) {
    }

    // A key store of type, written to name and protected by STORE_PASSWORD: the client key (its chain
    // the client certificate, then the CA) under each of keyAliases, and the CA as a trusted
    // certificate if trustCa.
    private static Path store(String name, String type, boolean trustCa, String... keyAliases) throws GeneralSecurityException, IOException {
        var store = KeyStore.getInstance(type);
        store.load(null, null);
        for (var alias : keyAliases)
            store.setKeyEntry(alias, TLS.clientKey, STORE_PASSWORD, new Certificate[] {TLS.client, TLS.ca});
        if (trustCa)
            store.setCertificateEntry("ca", TLS.ca);
        var file = TLS.directory.resolve(name);
        try (var out = Files.newOutputStream(file)) {
            store.store(out, STORE_PASSWORD);
        }
        return file;
    }

    private static IllegalArgumentException assertRefused(VaultTlsOptions.Builder tls) {
        return assertThrows(IllegalArgumentException.class, () -> tls.build().createSslContext());
    }

    @Test
    void keyStores_StandInForThePem_Pkcs12OrJks() throws Exception {
        var passwords = passwords();
        try (var vault = new FakeVault(TLS.serverContext(TLS.serverForHostAndIp, true), true)) {
            for (var type : List.of("PKCS12", "JKS")) {
                var tls = VaultTlsOptions.builder()
                        .trustStoreFile(store("trust." + type, type, true)).trustStorePassword(passwords.password())
                        .clientKeyStoreFile(store("client." + type, type, false, "client")).clientKeyStorePassword(passwords.password())
                        .passwordProtector(passwords.protector())
                        .build();
                assertFalse(tls.isEmpty());
                assertEquals(tls.trustStoreFile(), tls.toBuilder().build().trustStoreFile());
                try (var client = client(vault, tls)) {
                    await(client.readAsync(type));
                }
            }
            assertEquals(List.of("CN=hkdfguard-client", "CN=hkdfguard-client"), vault.clientCertificates);
        }
    }

    @Test
    void aKeyStore_NeedsItsPassword_ProtectedByThePasswordProtector() throws Exception {
        var passwords = passwords();
        var keys = store("refusals.p12", "PKCS12", true, "client");
        Supplier<VaultTlsOptions.Builder> keyStore = () -> VaultTlsOptions.builder().clientKeyStoreFile(keys)
                .passwordProtector(passwords.protector());

        assertRefused(keyStore.get());
        assertRefused(keyStore.get().clientKeyStorePassword(passwords.password()).passwordProtector(null));
        var otherRing = TestRings.ring().createProtector(VaultTlsOptions.PASSWORD_PURPOSE);
        assertRefused(keyStore.get().clientKeyStorePassword(VaultTlsOptions.protectPassword(otherRing, STORE_PASSWORD)));
        var otherPurpose = TestRings.protector();
        assertRefused(keyStore.get().clientKeyStorePassword(VaultTlsOptions.protectPassword(otherPurpose, STORE_PASSWORD)));
        // The password itself, never protected: refused without quoting it.
        var unprotected = assertRefused(keyStore.get().clientKeyStorePassword(new String(STORE_PASSWORD)));
        assertFalse(unprotected.getMessage().contains(new String(STORE_PASSWORD)), unprotected.getMessage());
        assertNull(unprotected.getCause());
        assertRefused(keyStore.get().clientKeyStorePassword(VaultTlsOptions.protectPassword(passwords.protector(), "wrong".toCharArray())));
        assertRefused(keyStore.get().clientKeyStorePassword(passwords.password()).clientCertificatePem(pem(TLS.client)));
        assertRefused(VaultTlsOptions.builder().clientKeyStoreFile(TLS.directory.resolve("missing.p12"))
                .clientKeyStorePassword(passwords.password()).passwordProtector(passwords.protector()));
        keyStore.get().clientKeyStorePassword(passwords.password()).build().createSslContext();

        Supplier<VaultTlsOptions.Builder> trustStore = () -> VaultTlsOptions.builder().trustStoreFile(keys)
                .passwordProtector(passwords.protector());
        assertRefused(trustStore.get());
        assertRefused(trustStore.get().trustStorePassword(passwords.password()).serverCertificatePem(TLS.caPem.getBytes(StandardCharsets.US_ASCII)));
        assertRefused(VaultTlsOptions.builder().trustStoreFile(store("no-ca.p12", "PKCS12", false, "client"))
                .trustStorePassword(passwords.password()).passwordProtector(passwords.protector()));
        trustStore.get().trustStorePassword(passwords.password()).build().createSslContext();
    }

    @Test
    void aClientKeyStoreWithMoreThanOneKey_NeedsTheAliasToPresent() throws Exception {
        var passwords = passwords();
        var keys = store("two-keys.p12", "PKCS12", false, "first", "second");
        Supplier<VaultTlsOptions.Builder> tls = () -> VaultTlsOptions.builder().clientKeyStoreFile(keys)
                .clientKeyStorePassword(passwords.password()).passwordProtector(passwords.protector());

        assertRefused(tls.get());
        assertRefused(tls.get().clientKeyStoreAlias("third"));
        tls.get().clientKeyStoreAlias("second").build().createSslContext();
        assertRefused(VaultTlsOptions.builder().clientKeyStoreFile(store("only-ca.p12", "PKCS12", true))
                .clientKeyStorePassword(passwords.password()).passwordProtector(passwords.protector()));
    }

    @Test
    void protectPassword_ProtectsWithThePasswordProtector_AndRefusesNoPassword() {
        var protector = TestRings.ring().createProtector(VaultTlsOptions.PASSWORD_PURPOSE);
        var protectedPassword = VaultTlsOptions.protectPassword(protector, STORE_PASSWORD);

        assertFalse(protectedPassword.contains(new String(STORE_PASSWORD)));
        assertEquals(new String(STORE_PASSWORD), TestRings.decrypt(protector, protectedPassword));
        assertThrows(IllegalArgumentException.class, () -> VaultTlsOptions.protectPassword(protector, new char[0]));
        assertThrows(NullPointerException.class, () -> VaultTlsOptions.protectPassword(protector, null));
        assertThrows(NullPointerException.class, () -> VaultTlsOptions.protectPassword(null, STORE_PASSWORD));
    }

    @Test
    void tlsOptions_CantBeAppliedToASuppliedHttpClient() {
        var tls = VaultTlsOptions.builder().insecureSkipVerify(true).build();
        try (var supplied = VaultHttp.newHttpClient()) {
            var e = assertThrows(IllegalArgumentException.class, () -> VaultHttp.httpClient(supplied, tls));
            assertTrue(e.getMessage().contains("SSLContext"), e.getMessage());
            assertSame(supplied, VaultHttp.httpClient(supplied, null));
            assertSame(supplied, VaultHttp.httpClient(supplied, VaultTlsOptions.builder().build()));
        }
        try (var own = VaultHttp.httpClient(null, tls)) {
            assertFalse(VaultHttp.followsRedirects(own));
        }
    }
}
