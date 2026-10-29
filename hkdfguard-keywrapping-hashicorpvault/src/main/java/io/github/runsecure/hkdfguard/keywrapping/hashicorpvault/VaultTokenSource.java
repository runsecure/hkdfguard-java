package io.github.runsecure.hkdfguard.keywrapping.hashicorpvault;

import java.util.concurrent.CompletableFuture;

/**
 * Supplies the Vault token every transit request is made with. Getting that token - logging in with
 * AppRole, Kubernetes or a certificate, renewing it, replacing it before it expires - is the
 * source's job, not the wrapper's, so any auth method can sit behind it.
 * {@link StaticVaultTokenSource} is a token you already hold.
 * <p>
 * The token is copied into a char array the wrapper owns and zeroes once the call is done, rather
 * than returned as a String that would live until collected. (The cache's VaultTokenProvider hands
 * its token over protected by the key ring instead; a key wrapper can't, since it runs before there
 * is a key ring.)
 */
@FunctionalInterface
public interface VaultTokenSource {
    /**
     * Copies the token to make the next request with into the start of destination. Asked for once
     * per wrap, unwrap or generate - not per retry. A token that is empty, longer than destination,
     * or isn't printable ASCII without spaces fails the call.
     * <p>
     * The wrapper waits for the returned future for at most its
     * {@link HashiCorpVaultTransitKeyWrapperOptions#timeout() timeout}, and cancels it if it hasn't
     * completed by then or the call is cancelled first. Write to destination only before completing
     * the future: once it completes, or is cancelled, the wrapper zeroes destination and forgets it.
     * A source's failure, whether thrown or completing the future exceptionally, fails the call and
     * isn't retried: retrying a login is the source's own business.
     *
     * @param destination where to write the token: {@link HashiCorpVaultTransitKeyWrapperImpl#MAX_TOKEN_LENGTH}
     *                    characters
     * @return completes with the number of characters written
     */
    CompletableFuture<Integer> copyTokenAsync(char[] destination);
}
