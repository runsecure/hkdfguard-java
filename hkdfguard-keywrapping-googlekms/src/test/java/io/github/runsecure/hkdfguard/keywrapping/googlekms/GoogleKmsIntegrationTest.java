package io.github.runsecure.hkdfguard.keywrapping.googlekms;

import static io.github.runsecure.hkdfguard.keywrapping.googlekms.Futures.assertFailsWith;
import static io.github.runsecure.hkdfguard.keywrapping.googlekms.Futures.await;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.google.cloud.kms.v1.KeyManagementServiceClient;
import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Real calls against a symmetric Cloud KMS key the caller provides. The client signs in with
 * Application Default Credentials (gcloud auth application-default login, or the attached service
 * account):
 * <pre>
 * ./mvnw -pl hkdfguard-keywrapping-googlekms -am verify
 * </pre>
 * Without HKDFGUARD_TEST_GOOGLE_KMS_KEY_NAME, in the environment or google.test.properties at the
 * repository root, every test here is reported as skipped - never as passed. The principal needs
 * roles/cloudkms.cryptoKeyEncrypterDecrypter on the key; the tests never create, alter or destroy a
 * key.
 */
class GoogleKmsIntegrationTest {
    private static final String CONTEXT = "hkdfguard.integrationtest";

    private static final SecureRandom RANDOM = new SecureRandom();

    private String keyName;
    private KeyManagementServiceClient client;

    // The key name first: a placeholder left in google.test.properties is reported as that, not as
    // whatever creating the client fails with.
    @BeforeEach
    void requireAKey() throws IOException {
        keyName = GoogleKmsTestEnvironment.assumeKeyName();
        client = KeyManagementServiceClient.create();
    }

    @AfterEach
    void closeTheClient() {
        if (client != null)
            client.close();
    }

    @Test
    void wrapThenUnwrap_RoundTripsA32ByteDek() {
        var wrapper = new GoogleKmsKeyWrapperImpl(client, keyName, CONTEXT);
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
        var wrapper = new GoogleKmsKeyWrapperImpl(client, keyName, CONTEXT);

        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.generateAndWrapAsync(wrapped));
        var revealed = new byte[32];

        assertEquals(32, await(wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), revealed)));
        assertFalse(ArrayUtility.isNullOrEmpty(revealed));
    }

    @Test
    void unwrap_UnderAnotherContext_IsRefused() {
        var wrapper = new GoogleKmsKeyWrapperImpl(client, keyName, CONTEXT);
        var other = new GoogleKmsKeyWrapperImpl(client, keyName, "hkdfguard.integrationtest.other");

        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.generateAndWrapAsync(wrapped));

        assertFailsWith(CryptographicException.class, other.unwrapAsync(Arrays.copyOf(wrapped, length), new byte[32]));
    }

    @Test
    void unwrap_WhenTampered_IsRefused() {
        var wrapper = new GoogleKmsKeyWrapperImpl(client, keyName, CONTEXT);

        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.generateAndWrapAsync(wrapped));
        wrapped[length - 1] ^= 1;

        assertFailsWith(CryptographicException.class, wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), new byte[32]));
    }
}
