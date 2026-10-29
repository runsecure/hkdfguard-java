package io.github.runsecure.hkdfguard.cache.googlesecretmanager;

import static io.github.runsecure.hkdfguard.cache.googlesecretmanager.Futures.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.cloud.secretmanager.v1.SecretName;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import java.io.IOException;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Real calls against a secret the caller provides. The cache's client signs in with Application
 * Default Credentials (gcloud auth application-default login, or the attached service account):
 * <pre>
 * HKDFGUARD_TEST_GOOGLE_SECRET_NAME=projects/{project}/secrets/{secret} \
 * ./mvnw -pl hkdfguard-cache-googlesecretmanager verify
 * </pre>
 * Without HKDFGUARD_TEST_GOOGLE_SECRET_NAME, in the environment or google.test.properties at the
 * repository root, every test here is reported as skipped - never as passed. The principal needs
 * only secretmanager.versions.access on that secret (the Secret Manager Secret Accessor role); the
 * tests never list, create, alter or delete a secret.
 */
class GoogleSecretManagerIntegrationTest {
    private SecretName secret;
    private KeyRingImpl ring;
    private GoogleSecretManagerSecretCacheImpl cache;

    // The secret name first: a placeholder left in google.test.properties is reported as that, not
    // as whatever creating the client fails with.
    @BeforeEach
    void requireASecret() throws IOException {
        secret = GoogleSecretManagerTestEnvironment.assumeSecretName();
        ring = TestRings.ring();
        cache = GoogleSecretManagerSecretCacheImpl.create(secret.getProject(), ring, null);
    }

    @AfterEach
    void closeTheCache() {
        if (cache != null)
            cache.close();
        if (ring != null)
            ring.close();
    }

    @Test
    void decrypt_RevealsTheSecret() {
        var max = cache.findMaxDecryptedLength(secret.getSecret()).orElseThrow();

        assertTrue(max > 0);
        assertTrue(cache.decrypt(secret.getSecret(), new byte[max]) > 0);
    }

    @Test
    void decryptAsync_RevealsTheSecret() {
        var max = await(cache.findMaxDecryptedLengthAsync(secret.getSecret())).orElseThrow();

        assertTrue(max > 0);
        assertTrue(await(cache.decryptAsync(secret.getSecret(), new byte[max])) > 0);
    }

    @Test
    void decrypt_OfASecretThatDoesNotExist_ReturnsZero() {
        var missing = "hkdfguard-missing-" + UUID.randomUUID().toString().replace("-", "");

        assertEquals(0, cache.decrypt(missing, new byte[16]));
    }
}
