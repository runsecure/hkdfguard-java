package io.github.runsecure.hkdfguard.keywrapping.hashicorpvault;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.remote.VaultHttp;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * A token issued elsewhere - VAULT_TOKEN, say - held in a char array of its own and zeroed on
 * {@link #close}. Nothing renews or replaces it, so once it expires or is revoked every request
 * fails with 403.
 */
public final class StaticVaultTokenSource implements VaultTokenSource, AutoCloseable {
    private final char[] token;

    /**
     * @param token the token, copied. It is read-only, so it isn't cleared here: pass a
     *              {@code CharBuffer.wrap(char[])} to keep the token out of String, and clear the
     *              array once this returns.
     * @throws NullPointerException     token is null
     * @throws IllegalArgumentException token is empty, longer than
     *                                  {@link HashiCorpVaultTransitKeyWrapperImpl#MAX_TOKEN_LENGTH},
     *                                  or isn't printable ASCII without spaces
     */
    public StaticVaultTokenSource(CharSequence token) {
        Objects.requireNonNull(token, "token");
        if (token.length() > HashiCorpVaultTransitKeyWrapperImpl.MAX_TOKEN_LENGTH || !VaultHttp.isValidToken(token))
            throw new IllegalArgumentException("A Vault token is 1-" + HashiCorpVaultTransitKeyWrapperImpl.MAX_TOKEN_LENGTH
                    + " printable ASCII characters, with no spaces.");

        this.token = new char[token.length()];
        for (var i = 0; i < this.token.length; i++)
            this.token[i] = token.charAt(i);
    }

    /**
     * {@inheritDoc}
     *
     * @throws NullPointerException     destination is null
     * @throws IllegalArgumentException destination is too small for the token
     */
    @Override
    public CompletableFuture<Integer> copyTokenAsync(char[] destination) {
        Objects.requireNonNull(destination, "destination");
        if (destination.length < token.length)
            throw new IllegalArgumentException("The token is " + token.length + " characters; destination holds " + destination.length + ".");

        System.arraycopy(token, 0, destination, 0, token.length);
        return CompletableFuture.completedFuture(token.length);
    }

    /** Zeroes the token. A request made afterwards fails, its token no longer one. */
    @Override
    public void close() {
        ArrayUtility.zeroMemory(token);
    }
}
