package io.github.runsecure.hkdfguard.cache.hashicorpvault;

import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * A token issued elsewhere - VAULT_TOKEN, say - held only in protected form. Nothing renews or
 * replaces it, so once it expires or is revoked every fetch fails with 403.
 */
public final class StaticVaultToken implements VaultTokenProvider {
    private final String protectedToken;

    /**
     * @param protectedToken the token as the cache's token protector protected it
     *                       ({@code tokenProtector.encrypt(token)}), never the token itself; see
     *                       {@link #protect}
     * @throws NullPointerException     protectedToken is null
     * @throws IllegalArgumentException protectedToken is empty or whitespace
     */
    public StaticVaultToken(String protectedToken) {
        Objects.requireNonNull(protectedToken, "protectedToken");
        if (protectedToken.isBlank())
            throw new IllegalArgumentException("The protected token must not be empty or whitespace.");
        this.protectedToken = protectedToken;
    }

    /**
     * Protects token with tokenProtector - the protector the cache is given - and holds only the
     * result. token is read-only, so it isn't cleared here: pass a {@code CharBuffer.wrap(char[])}
     * to keep the token out of String, and clear the array once this returns.
     *
     * @throws NullPointerException     tokenProtector or token is null
     * @throws IllegalArgumentException token is empty, or isn't printable ASCII without spaces
     */
    public static StaticVaultToken protect(DataProtector tokenProtector, CharSequence token) {
        Objects.requireNonNull(tokenProtector, "tokenProtector");
        Objects.requireNonNull(token, "token");
        if (!HashiCorpVaultSecretCacheImpl.isValidToken(token))
            throw new IllegalArgumentException("A Vault token is printable ASCII, with no spaces.");

        return new StaticVaultToken(tokenProtector.encrypt(token));
    }

    @Override
    public CompletableFuture<String> getTokenAsync() {
        return CompletableFuture.completedFuture(protectedToken);
    }
}
