package io.github.runsecure.hkdfguard.cache.hashicorpvault;

import static io.github.runsecure.hkdfguard.cache.hashicorpvault.Futures.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.UUID;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Real reads of a secret the caller provides, in a KV version 2 engine mounted at "secret" (a dev
 * server's default), with a token the caller provides:
 * <pre>
 * vault kv put secret/hkdfguard/test value=s3cret
 * HKDFGUARD_TEST_VAULT_ADDR=https://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TOKEN=... \
 * HKDFGUARD_TEST_VAULT_CACERT=/path/to/vault-ca.pem HKDFGUARD_TEST_VAULT_SECRET_NAME=hkdfguard/test#value \
 * ./mvnw -pl hkdfguard-cache-hashicorpvault verify
 * </pre>
 * Without HKDFGUARD_TEST_VAULT_SECRET_NAME every test here is reported as skipped - never as passed.
 * HKDFGUARD_TEST_VAULT_CACERT is needed only for a server certificate the JDK's trust store doesn't
 * trust. The token needs only read on that secret's path; the tests never list, write or delete.
 */
class HashiCorpVaultIntegrationTest {
    private String secretName;
    private KeyRingImpl ring;
    private HttpClient client;
    private HashiCorpVaultSecretCacheImpl cache;

    @BeforeEach
    void requireASecret() {
        secretName = HashiCorpVaultTestEnvironment.assumeSecretName();
        ring = TestRings.ring();
        var protector = ring.createProtector(HashiCorpVaultSecretCacheImpl.TOKEN_PURPOSE);
        var token = StaticVaultToken.protect(protector, HashiCorpVaultTestEnvironment.token());
        client = trustingTheConfiguredCa();
        cache = new HashiCorpVaultSecretCacheImpl(HashiCorpVaultTestEnvironment.address(), token, protector, ring,
                HashiCorpVaultSecretCacheOptions.builder().httpClient(client).build(), null);
    }

    @AfterEach
    void closeEverything() {
        if (cache != null)
            cache.close();
        if (client != null)
            client.close();
        if (ring != null)
            ring.close();
    }

    @Test
    void decrypt_RevealsTheSecret() {
        var max = cache.findMaxDecryptedLength(secretName).orElseThrow();

        assertTrue(cache.decrypt(secretName, new byte[max]) > 0);
    }

    @Test
    void decryptAsync_RevealsTheSecret() {
        var max = await(cache.findMaxDecryptedLengthAsync(secretName)).orElseThrow();

        assertTrue(max > 0);
        assertTrue(await(cache.decryptAsync(secretName, new byte[max])) > 0);
    }

    @Test
    void decrypt_OfASecretThatDoesNotExist_ReturnsZero() {
        assertEquals(0, cache.decrypt("hkdfguard/missing-" + UUID.randomUUID().toString().replace("-", ""), new byte[16]));
    }

    // A client trusting HKDFGUARD_TEST_VAULT_CACERT, and only it, when set; otherwise the JDK's
    // default trust store. Either way it follows no redirects.
    private static HttpClient trustingTheConfiguredCa() {
        var builder = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER);
        var caCertificate = HashiCorpVaultTestEnvironment.caCertificate();
        if (caCertificate == null)
            return builder.build();

        try (var in = Files.newInputStream(caCertificate)) {
            var trusted = KeyStore.getInstance(KeyStore.getDefaultType());
            trusted.load(null, null);
            var index = 0;
            for (var certificate : CertificateFactory.getInstance("X.509").generateCertificates(in))
                trusted.setCertificateEntry("ca-" + index++, certificate);

            var trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trusted);
            var tls = SSLContext.getInstance("TLS");
            tls.init(null, trustManagers.getTrustManagers(), null);
            return builder.sslContext(tls).build();
        } catch (IOException e) {
            throw new UncheckedIOException("Could not read " + caCertificate + ".", e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not trust " + caCertificate + ".", e);
        }
    }
}
