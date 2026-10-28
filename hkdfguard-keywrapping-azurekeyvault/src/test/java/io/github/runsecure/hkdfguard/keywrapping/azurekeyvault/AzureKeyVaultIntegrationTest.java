package io.github.runsecure.hkdfguard.keywrapping.azurekeyvault;

import static io.github.runsecure.hkdfguard.keywrapping.azurekeyvault.Futures.assertFailsWith;
import static io.github.runsecure.hkdfguard.keywrapping.azurekeyvault.Futures.await;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.azure.identity.DefaultAzureCredentialBuilder;
import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Real calls against an RSA wrapping key and an EC P-256 signing key the caller provides, named in
 * azure.test.properties at the repository root (or the environment; see AzureKeyVaultTestEnvironment).
 * Credentials come from DefaultAzureCredential (environment, workload or managed identity, Azure
 * CLI, ...):
 * <pre>
 * az login
 * ./mvnw -pl hkdfguard-keywrapping-azurekeyvault -am verify
 * </pre>
 * Without both keys every test here is reported as skipped - never as passed. The principal
 * needs wrapKey and unwrapKey on the RSA key, and sign and verify on the EC key (the Key Vault
 * Crypto User role on each); the tests never create, alter or delete a key. The HTTP client is the
 * JDK's (azure-core-http-jdk-httpclient, a test dependency).
 */
class AzureKeyVaultIntegrationTest {
    private static final String CONTEXT = "hkdfguard.integrationtest";

    private static final SecureRandom RANDOM = new SecureRandom();

    private AzureKeyVaultTestEnvironment.Keys keys;

    @BeforeEach
    void requireKeys() {
        keys = AzureKeyVaultTestEnvironment.assumeKeys();
    }

    private AzureKeyVaultKeyWrapperImpl wrapper(String context) {
        return new AzureKeyVaultKeyWrapperImpl(keys.wrappingKeyId(), keys.signingKeyId(), new DefaultAzureCredentialBuilder().build(), context);
    }

    @Test
    void wrapThenUnwrap_RoundTripsA32ByteDek() {
        var wrapper = wrapper(CONTEXT);
        var dek = new byte[32];
        RANDOM.nextBytes(dek);

        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.wrapAsync(dek, wrapped));
        var revealed = new byte[32];

        assertEquals(32, await(wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), revealed)));
        assertArrayEquals(dek, revealed);
    }

    @Test
    void generateAndWrap_ProducesAWrappedDekThatReveals() {
        var wrapper = wrapper(CONTEXT);

        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.generateAndWrapAsync(wrapped));
        var revealed = new byte[32];

        assertEquals(32, await(wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), revealed)));
        assertFalse(ArrayUtility.isNullOrEmpty(revealed));
    }

    @Test
    void unwrap_UnderAnotherContext_IsRefused() {
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper(CONTEXT).generateAndWrapAsync(wrapped));

        assertFailsWith(CryptographicException.class, wrapper(CONTEXT + ".other").unwrapAsync(Arrays.copyOf(wrapped, length), new byte[32]));
    }

    @Test
    void unwrap_WhenTampered_IsRefused() {
        var wrapper = wrapper(CONTEXT);
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.generateAndWrapAsync(wrapped));
        wrapped[WrappedDekEnvelope.HEADER_LENGTH + 10] ^= 1;

        assertFailsWith(CryptographicException.class, wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), new byte[32]));
    }
}
