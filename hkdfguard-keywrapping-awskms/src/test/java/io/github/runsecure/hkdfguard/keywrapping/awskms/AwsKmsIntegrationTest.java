package io.github.runsecure.hkdfguard.keywrapping.awskms;

import static io.github.runsecure.hkdfguard.keywrapping.awskms.Futures.await;
import static io.github.runsecure.hkdfguard.keywrapping.awskms.Futures.awaitFailure;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient;
import software.amazon.awssdk.services.kms.KmsAsyncClient;

/**
 * Real calls against a symmetric AWS KMS key the caller provides. The SDK resolves credentials and
 * region the usual way (environment, profile, container or instance role):
 * <pre>
 * HKDFGUARD_TEST_AWS_KMS_KEY_ID=arn:aws:kms:... AWS_REGION=us-east-1 ./mvnw -pl hkdfguard-keywrapping-awskms -am verify
 * </pre>
 * Without HKDFGUARD_TEST_AWS_KMS_KEY_ID every test here is reported as skipped - never as passed.
 * The principal needs kms:Encrypt, kms:Decrypt and kms:GenerateDataKeyWithoutPlaintext on the key;
 * the tests never create, alter or schedule deletion of a key.
 */
class AwsKmsIntegrationTest {
    private static final Map<String, String> CONTEXT = Map.of("purpose", "hkdfguard.integrationtest");

    private static final SecureRandom RANDOM = new SecureRandom();

    private String keyId;
    private KmsAsyncClient client;

    @BeforeEach
    void requireAKey() {
        keyId = AwsKmsTestEnvironment.assumeKeyId();
        // The application chooses the HTTP client; these tests use the SDK's Netty one.
        client = KmsAsyncClient.builder().httpClientBuilder(NettyNioAsyncHttpClient.builder()).build();
    }

    @AfterEach
    void closeTheClient() {
        if (client != null)
            client.close();
    }

    @Test
    void wrapThenUnwrap_RoundTripsA32ByteDek() {
        var wrapper = new AwsKmsKeyWrapperImpl(client, keyId, CONTEXT);
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
        var wrapper = new AwsKmsKeyWrapperImpl(client, keyId, CONTEXT);

        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.generateAndWrapAsync(wrapped));
        var revealed = new byte[32];

        assertEquals(32, await(wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), revealed)));
        assertFalse(ArrayUtility.isNullOrEmpty(revealed));
    }

    @Test
    void unwrap_UnderAnotherContext_IsRefused() {
        var wrapper = new AwsKmsKeyWrapperImpl(client, keyId, CONTEXT);
        var other = new AwsKmsKeyWrapperImpl(client, keyId, Map.of("purpose", "hkdfguard.integrationtest.other"));

        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.generateAndWrapAsync(wrapped));

        awaitFailure(CryptographicException.class, other.unwrapAsync(Arrays.copyOf(wrapped, length), new byte[32]));
    }

    @Test
    void unwrap_WhenTampered_IsRefused() {
        var wrapper = new AwsKmsKeyWrapperImpl(client, keyId, CONTEXT);

        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.generateAndWrapAsync(wrapped));
        wrapped[length - 1] ^= 1;

        awaitFailure(CryptographicException.class, wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), new byte[32]));
    }
}
