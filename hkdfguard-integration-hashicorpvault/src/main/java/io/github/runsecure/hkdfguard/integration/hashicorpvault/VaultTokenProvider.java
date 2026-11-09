package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.util.concurrent.CompletableFuture;

/**
 * Supplies a Vault token, protected: as the token protector of whatever uses it encrypted it
 * ({@code tokenProtector.encrypt(token)}), never the token itself - {@link VaultClient}'s, or the
 * HashiCorp Vault secret cache's. Asked for once per request or fetch; the token is decrypted only
 * to put it in that request's X-Vault-Token header. Logging in with AppRole, Kubernetes or a
 * certificate, renewing and replacing tokens are the provider's business, so any auth method can
 * sit behind it; {@link StaticVaultToken} is a token you already hold. Code that runs before there
 * is a key ring uses {@link VaultTokenSource} instead.
 */
@FunctionalInterface
public interface VaultTokenProvider {
    /**
     * The token to make the next request with, protected by the user's token protector. A token
     * that isn't protected so fails the request with IllegalStateException.
     * <p>
     * The user waits for the returned future for at most its timeout, and cancels it if it hasn't
     * completed by then or the request is cancelled first. A provider's failure, whether thrown or
     * completing the future exceptionally, fails the request and isn't retried: retrying a login is
     * the provider's own business.
     *
     * @return completes with the protected token
     */
    CompletableFuture<String> getTokenAsync();
}
