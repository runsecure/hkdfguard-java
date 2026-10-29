package io.github.runsecure.hkdfguard.cache.awssecretsmanager;

import static io.github.runsecure.hkdfguard.cache.awssecretsmanager.Futures.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.http.nio.netty.NettyNioAsyncHttpClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerAsyncClient;

/**
 * Real calls against a secret the caller provides, as the principal whose access keys are in the
 * environment or the shared credentials file (see AwsSecretsManagerTestEnvironment.credentials);
 * the region comes from the SDK's default chain:
 * <pre>
 * aws configure
 * HKDFGUARD_TEST_AWS_SECRET_NAME=prod/my-secret ./mvnw -pl hkdfguard-cache-awssecretsmanager verify
 * </pre>
 * Without HKDFGUARD_TEST_AWS_SECRET_NAME, in the environment or aws.test.properties at the
 * repository root, every test here is reported as skipped - never as passed. The principal needs
 * only secretsmanager:GetSecretValue on that secret (and kms:Decrypt on its key, if it isn't the
 * AWS managed one); the tests never list, create, alter or delete a secret.
 */
class AwsSecretsManagerIntegrationTest {
    private String secretName;
    private SecretsManagerAsyncClient client;
    private KeyRingImpl ring;

    @BeforeEach
    void requireASecret() {
        secretName = AwsSecretsManagerTestEnvironment.assumeSecretName();
        // The application chooses the HTTP client; these tests use the SDK's Netty one.
        client = SecretsManagerAsyncClient.builder()
                .httpClientBuilder(NettyNioAsyncHttpClient.builder())
                .credentialsProvider(AwsSecretsManagerTestEnvironment.credentials())
                .build();
        ring = TestRings.ring();
    }

    @AfterEach
    void close() {
        if (client != null)
            client.close();
        if (ring != null)
            ring.close();
    }

    @Test
    void decrypt_RevealsTheSecret() {
        var cache = new AwsSecretsManagerSecretCacheImpl(client, ring, null);

        var max = cache.findMaxDecryptedLength(secretName).orElseThrow();
        assertTrue(cache.decrypt(secretName, new byte[max]) > 0);
    }

    @Test
    void decryptAsync_RevealsTheSecret() {
        var cache = new AwsSecretsManagerSecretCacheImpl(client, ring, null);

        var max = await(cache.findMaxDecryptedLengthAsync(secretName)).orElseThrow();
        assertTrue(max > 0);
        assertTrue(await(cache.decryptAsync(secretName, new byte[max])) > 0);
    }

    @Test
    void decrypt_OfASecretThatDoesNotExist_ReturnsZero() {
        var cache = new AwsSecretsManagerSecretCacheImpl(client, ring, null);

        // Beside the configured secret, so a policy granting GetSecretValue on its path covers it:
        // without permission, Secrets Manager answers AccessDenied even for a secret that doesn't exist.
        var folder = secretName.substring(0, secretName.lastIndexOf('/') + 1);
        assertEquals(0, cache.decrypt(folder + "hkdfguard-missing-" + UUID.randomUUID().toString().replace("-", ""), new byte[16]));
    }
}
