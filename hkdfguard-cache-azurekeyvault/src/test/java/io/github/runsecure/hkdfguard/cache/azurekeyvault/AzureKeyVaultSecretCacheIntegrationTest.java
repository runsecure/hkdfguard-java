package io.github.runsecure.hkdfguard.cache.azurekeyvault;

import static io.github.runsecure.hkdfguard.cache.azurekeyvault.Futures.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecretIdentifier;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Real calls against a secret the caller provides, named in azure.test.properties at the repository
 * root (or the environment; see AzureKeyVaultTestEnvironment). Credentials come from
 * DefaultAzureCredential (environment, workload or managed identity, Azure CLI, ...):
 * <pre>
 * az login
 * HKDFGUARD_TEST_AZURE_SECRET_ID=https://{vault}.vault.azure.net/secrets/{name} \
 * ./mvnw -pl hkdfguard-cache-azurekeyvault -am verify
 * </pre>
 * Without the secret every test here is reported as skipped - never as passed. The principal needs
 * only get on secrets (the Key Vault Secrets User role); the tests never list, create, alter or
 * delete a secret. The HTTP client is the JDK's (azure-core-http-jdk-httpclient, a test dependency).
 */
class AzureKeyVaultSecretCacheIntegrationTest {
    private KeyVaultSecretIdentifier secretId;
    private KeyRingImpl ring;

    @BeforeEach
    void requireSecret() {
        secretId = AzureKeyVaultTestEnvironment.assumeSecret();
        ring = TestRings.ring();
    }

    @AfterEach
    void closeRing() {
        if (ring != null)
            ring.close();
    }

    private AzureKeyVaultSecretCacheImpl create() {
        return new AzureKeyVaultSecretCacheImpl(new SecretClientBuilder()
                .vaultUrl(secretId.getVaultUrl())
                .credential(new DefaultAzureCredentialBuilder().build()), ring);
    }

    @Test
    void decrypt_RevealsTheSecret() {
        var cache = create();

        var max = cache.findMaxDecryptedLength(secretId.getName());
        assertTrue(max.isPresent());
        assertTrue(cache.decrypt(secretId.getName(), new char[max.getAsInt()]) > 0);
    }

    @Test
    void decryptAsync_RevealsTheSecret() {
        var cache = create();

        var max = await(cache.findMaxDecryptedLengthAsync(secretId.getName()));
        assertTrue(max.isPresent());
        assertTrue(await(cache.decryptAsync(secretId.getName(), new char[max.getAsInt()])) > 0);
    }

    @Test
    void decrypt_OfASecretThatDoesNotExist_ReturnsZero() {
        var cache = create();

        assertEquals(0, cache.decrypt("hkdfguard-missing-" + UUID.randomUUID().toString().replace("-", ""), new byte[16]));
    }
}
