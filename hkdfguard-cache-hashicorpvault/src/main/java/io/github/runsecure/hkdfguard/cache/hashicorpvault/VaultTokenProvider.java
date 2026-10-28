package io.github.runsecure.hkdfguard.cache.hashicorpvault;

import java.util.concurrent.CompletableFuture;

/**
 * Supplies the Vault token every read is made with, protected: as the cache's token protector
 * encrypted it ({@code tokenProtector.encrypt(token)}), never the token itself. Getting that token -
 * logging in with AppRole, Kubernetes or a certificate, renewing it, replacing it before it expires
 * - is the provider's job, not the cache's, so any auth method can sit behind the cache.
 * {@link StaticVaultToken} is a token you already hold.
 */
public interface VaultTokenProvider {
    /**
     * The token to make the next read with, protected by the cache's token protector. Asked for on
     * every fetch; the cache never keeps it, and decrypts it only to put it in that fetch's
     * requests. A token that isn't protected so fails the fetch.
     * <p>
     * The cache waits for the returned future for at most its
     * {@link HashiCorpVaultSecretCacheOptions#timeout() timeout}, and cancels it if it hasn't
     * completed by then or the fetch is cancelled first. A provider's failure, whether thrown or
     * completing the future exceptionally, fails the fetch and isn't retried: retrying a login is
     * the provider's own business.
     *
     * @return completes with the protected token
     */
    CompletableFuture<String> getTokenAsync();
}
