package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.util.concurrent.CompletableFuture;

/**
 * Supplies a Vault token in plaintext, for code that runs before there is a key ring to protect it
 * with - the HashiCorp Vault transit key wrapper, whose key ring depends on it. Getting that token -
 * logging in with AppRole, Kubernetes or a certificate, renewing it, replacing it before it expires
 * - is the source's job, so any auth method can sit behind it. {@link StaticVaultTokenSource} is a
 * token you already hold.
 * <p>
 * The token is copied into a char array the caller owns and zeroes once the request has been sent,
 * rather than returned as a String that would live until collected. Once there is a key ring,
 * prefer {@link VaultTokenProvider}, which hands its token over protected by it.
 */
@FunctionalInterface
public interface VaultTokenSource {
    /**
     * Copies the token to make the next request with into the start of destination. Asked for once
     * per operation, not per retry (the transit key wrapper asks once per wrap, unwrap or generate).
     * A token that is empty, longer than destination, or isn't printable ASCII without spaces fails
     * the operation.
     * <p>
     * The caller waits for the returned future for at most its timeout, and cancels it if it hasn't
     * completed by then or the operation is cancelled first. Write to destination only before
     * completing the future: once it completes, or is cancelled, the caller zeroes destination and
     * forgets it. A source's failure, whether thrown or completing the future exceptionally, fails
     * the operation and isn't retried: retrying a login is the source's own business.
     *
     * @param destination where to write the token: {@link VaultHttp#MAX_TOKEN_LENGTH} characters
     * @return completes with the number of characters written
     */
    CompletableFuture<Integer> copyTokenAsync(char[] destination);
}
