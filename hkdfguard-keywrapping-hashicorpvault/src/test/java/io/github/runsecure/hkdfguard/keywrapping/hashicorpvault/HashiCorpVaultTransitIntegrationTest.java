package io.github.runsecure.hkdfguard.keywrapping.hashicorpvault;

import static io.github.runsecure.hkdfguard.keywrapping.hashicorpvault.Futures.assertFailsWith;
import static io.github.runsecure.hkdfguard.keywrapping.hashicorpvault.Futures.await;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Real calls against a transit key the caller provides, with a token the caller provides - on a dev
 * server, the ones scripts/provision-vault-transit-test-key.sh creates and prints:
 * <pre>
 * HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TOKEN=... \
 * HKDFGUARD_TEST_VAULT_TRANSIT_KEY=hkdfguard-test HKDFGUARD_TEST_VAULT_TRANSIT_OTHER_KEY=hkdfguard-test-other \
 * ./mvnw -pl hkdfguard-keywrapping-hashicorpvault -am verify
 * </pre>
 * Without HKDFGUARD_TEST_VAULT_TRANSIT_KEY, in the environment or vault.test.properties at the
 * repository root, every test here is reported as skipped - never as passed.
 * HKDFGUARD_TEST_VAULT_TRANSIT_MOUNT names a mount other than "transit", and
 * HKDFGUARD_TEST_VAULT_CACERT a CA for a server certificate the JDK's trust store doesn't trust. The
 * token needs only update on encrypt, decrypt and datakey/wrapped for the keys; the tests never
 * create, rotate, read or delete a key.
 */
class HashiCorpVaultTransitIntegrationTest {
    private static final String CONTEXT = "hkdfguard.integrationtest";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final List<AutoCloseable> closeables = new ArrayList<>();
    private String key;
    private HttpClient client;

    @BeforeEach
    void requireAKey() {
        key = VaultTransitTestEnvironment.assumeKey();
        client = VaultTransitTestEnvironment.client();
    }

    @AfterEach
    void closeEverything() throws Exception {
        for (var closeable : closeables.reversed())
            closeable.close();
        if (client != null)
            client.close();
    }

    private HashiCorpVaultTransitKeyWrapperImpl create(String context, String keyName) {
        var tokens = new StaticVaultTokenSource(VaultTransitTestEnvironment.token());
        closeables.add(tokens);
        var wrapper = new HashiCorpVaultTransitKeyWrapperImpl(VaultTransitTestEnvironment.address(), keyName, tokens, context, null,
                VaultTransitTestEnvironment.options(client));
        closeables.add(wrapper);
        return wrapper;
    }

    private HashiCorpVaultTransitKeyWrapperImpl create(String context) {
        return create(context, key);
    }

    private static byte[] generate(HashiCorpVaultTransitKeyWrapperImpl wrapper) {
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        return Arrays.copyOf(wrapped, await(wrapper.generateAndWrapAsync(wrapped)));
    }

    @Test
    void wrapThenUnwrap_RoundTripsA32ByteDek() {
        var wrapper = create(CONTEXT);
        var dek = new byte[32];
        RANDOM.nextBytes(dek);

        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.wrapAsync(dek, wrapped));
        var revealed = new byte[32];

        assertTrue(new String(wrapped, 0, length, StandardCharsets.US_ASCII).startsWith("vault:v"));
        assertEquals(32, await(wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), revealed)));
        assertArrayEquals(dek, revealed);
    }

    @Test
    void generateAndWrap_InVault_ProducesAWrappedDekThatReveals() {
        // No context: Vault generates the DEK with datakey/wrapped.
        var wrapper = create(null);

        var wrapped = generate(wrapper);
        var revealed = new byte[32];

        assertEquals(32, await(wrapper.unwrapAsync(wrapped, revealed)));
        assertFalse(ArrayUtility.isNullOrEmpty(revealed));
    }

    @Test
    void generateAndWrap_WithAContext_ProducesAWrappedDekThatReveals() {
        var wrapper = create(CONTEXT);

        var wrapped = generate(wrapper);
        var revealed = new byte[32];

        assertEquals(32, await(wrapper.unwrapAsync(wrapped, revealed)));
        assertFalse(ArrayUtility.isNullOrEmpty(revealed));
    }

    @Test
    void unwrap_UnderAnotherContext_OrNone_IsRefused() {
        var wrapper = create(CONTEXT);
        var other = create("hkdfguard.integrationtest.other");
        var none = create(null);

        var wrapped = generate(wrapper);

        assertFailsWith(CryptographicException.class, other.unwrapAsync(wrapped, new byte[32]));
        assertFailsWith(CryptographicException.class, none.unwrapAsync(wrapped, new byte[32]));
    }

    @Test
    void unwrap_WhenTampered_IsRefused() {
        var wrapper = create(CONTEXT);

        var wrapped = generate(wrapper);
        // Another base64 character, so it reaches Vault and fails there.
        wrapped[12] = wrapped[12] == 'A' ? (byte) 'B' : (byte) 'A';

        var e = assertFailsWith(CryptographicException.class, wrapper.unwrapAsync(wrapped, new byte[32]));
        assertTrue(e.getMessage().contains("400"), e.getMessage());
    }

    @Test
    void unwrap_UnderAnotherKey_IsRefused() {
        var otherKey = VaultTransitTestEnvironment.assumeOtherKey();
        var wrapper = create(CONTEXT);
        var other = create(CONTEXT, otherKey);

        var wrapped = generate(wrapper);

        assertFailsWith(CryptographicException.class, other.unwrapAsync(wrapped, new byte[32]));
    }

    @Test
    void anInvalidToken_IsRefusedWith403() {
        var tokens = new StaticVaultTokenSource("hvs.not-a-real-token");
        closeables.add(tokens);
        var wrapper = new HashiCorpVaultTransitKeyWrapperImpl(VaultTransitTestEnvironment.address(), key, tokens, null, null,
                VaultTransitTestEnvironment.options(client));
        closeables.add(wrapper);

        var e = assertFailsWith(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));
        assertTrue(e.getMessage().contains("403"), e.getMessage());
    }

    @Test
    void aCryptoProvider_GeneratesAndRevealsItsDekThroughVault() {
        var wrapper = create(CONTEXT);
        try (var provider = await(new AesGcmCryptoProviderFactoryImpl().createEphemeralAsync(wrapper, 60))) {
            var expected = "hello, vault transit".getBytes(StandardCharsets.UTF_8);
            var plaintext = expected.clone();
            var encrypted = new byte[provider.getEncryptedAllocationLength(plaintext.length)];
            int encryptedLength = provider.encrypt(plaintext, encrypted);
            var decrypted = new byte[provider.getDecryptedAllocationLength(encryptedLength)];
            int decryptedLength = provider.decrypt(Arrays.copyOf(encrypted, encryptedLength), decrypted);

            assertArrayEquals(expected, Arrays.copyOf(decrypted, decryptedLength));
        }
    }
}
