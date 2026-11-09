package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * A token held only in protected form: one issued elsewhere (VAULT_TOKEN, say), or one Vault
 * returned to a {@link VaultClient} - {@link VaultResponseAuth#clientToken()} after a login, or
 * {@link VaultResponseWrapInfo#token()} for a wrapped response - which the client protects as it
 * reads the response, so it never becomes a String. Nothing renews or replaces it, so once it
 * expires or is revoked every request fails with 403.
 */
public final class StaticVaultToken implements VaultTokenProvider {
    private final String protectedToken;

    /**
     * @param protectedToken the token as its user's token protector protected it
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
     * Protects token with tokenProtector - the protector the client or cache is given - and holds
     * only the result. token is read-only, so it isn't cleared here: pass a
     * {@code CharBuffer.wrap(char[])} to keep the token out of String, and clear the array once this
     * returns.
     *
     * @throws NullPointerException     tokenProtector or token is null
     * @throws IllegalArgumentException token is empty, or isn't printable ASCII without spaces
     */
    public static StaticVaultToken protect(DataProtector tokenProtector, CharSequence token) {
        Objects.requireNonNull(tokenProtector, "tokenProtector");
        Objects.requireNonNull(token, "token");
        if (!VaultHttp.isValidToken(token))
            throw new IllegalArgumentException("A Vault token is printable ASCII, with no spaces.");

        return new StaticVaultToken(tokenProtector.encrypt(token));
    }

    @Override
    public CompletableFuture<String> getTokenAsync() {
        return CompletableFuture.completedFuture(protectedToken);
    }

    /** The protected token: what {@link #getTokenAsync} completes with, never the token itself. */
    @Override
    public String toString() {
        return protectedToken;
    }
}
