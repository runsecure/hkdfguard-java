package io.github.runsecure.hkdfguard.keywrapping.azurekeyvault;

import com.azure.security.keyvault.keys.cryptography.CryptographyAsyncClient;
import com.azure.security.keyvault.keys.cryptography.models.KeyWrapAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.UnwrapResult;
import com.azure.security.keyvault.keys.cryptography.models.VerifyResult;
import com.azure.security.keyvault.keys.cryptography.models.WrapResult;
import java.util.concurrent.CompletableFuture;

/**
 * The four Key Vault calls {@link AzureKeyVaultKeyWrapperImpl} makes on one key identifier, as
 * {@link CryptographyAsyncClient}'s methods of the same names: the seam its tests replace with an
 * in-memory vault. Each returns as soon as the request is sent; cancelling a returned future cancels
 * the request.
 */
interface KeyVaultKeyClient {
    CompletableFuture<WrapResult> wrapKey(KeyWrapAlgorithm algorithm, byte[] key);

    CompletableFuture<UnwrapResult> unwrapKey(KeyWrapAlgorithm algorithm, byte[] encryptedKey);

    CompletableFuture<SignResult> signData(SignatureAlgorithm algorithm, byte[] data);

    CompletableFuture<VerifyResult> verifyData(SignatureAlgorithm algorithm, byte[] data, byte[] signature);

    /** The calls, made through {@code client}. Each subscribes to the client's Mono at once. */
    static KeyVaultKeyClient over(CryptographyAsyncClient client) {
        return new KeyVaultKeyClient() {
            @Override
            public CompletableFuture<WrapResult> wrapKey(KeyWrapAlgorithm algorithm, byte[] key) {
                return client.wrapKey(algorithm, key).toFuture();
            }

            @Override
            public CompletableFuture<UnwrapResult> unwrapKey(KeyWrapAlgorithm algorithm, byte[] encryptedKey) {
                return client.unwrapKey(algorithm, encryptedKey).toFuture();
            }

            @Override
            public CompletableFuture<SignResult> signData(SignatureAlgorithm algorithm, byte[] data) {
                return client.signData(algorithm, data).toFuture();
            }

            @Override
            public CompletableFuture<VerifyResult> verifyData(SignatureAlgorithm algorithm, byte[] data, byte[] signature) {
                return client.verifyData(algorithm, data, signature).toFuture();
            }
        };
    }
}
