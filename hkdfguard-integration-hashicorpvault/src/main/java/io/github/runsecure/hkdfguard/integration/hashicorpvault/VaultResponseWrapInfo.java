package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.time.OffsetDateTime;

/**
 * A wrapped response: the token that unwraps it, and about it.
 *
 * @param token           the wrapping token, protected by the client's token protector as the
 *                        response was read. Hand it to {@link VaultClient#unwrapAsync}.
 * @param accessor        the wrapping token's accessor
 * @param ttl             how long the wrapping token lasts, in seconds
 * @param creationTime    when the response was wrapped
 * @param creationPath    the path whose response was wrapped
 * @param wrappedAccessor when a token is wrapped, that token's accessor
 */
public record VaultResponseWrapInfo(
        StaticVaultToken token,
        String accessor,
        long ttl,
        OffsetDateTime creationTime,
        String creationPath,
        String wrappedAccessor) {
}
