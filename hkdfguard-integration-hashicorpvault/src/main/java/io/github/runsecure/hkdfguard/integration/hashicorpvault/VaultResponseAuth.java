package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.util.List;
import java.util.Map;

/**
 * The token a login issued, and about it.
 *
 * @param clientToken      the token, protected by the client's token protector as the response was
 *                         read - it never becomes a String. Hand it to
 *                         {@link VaultClient#setToken(VaultTokenProvider)} or
 *                         {@link VaultRequestOptions#token()}.
 * @param accessor         the token's accessor: for looking it up or revoking it, not for making requests
 * @param policies         every policy the token carries
 * @param tokenPolicies    the policies attached to the token itself
 * @param identityPolicies the policies the token gets from its identity
 * @param metadata         the auth method's metadata about the login
 * @param orphan           whether the token has no parent
 * @param entityId         the identity entity the token belongs to
 * @param leaseDuration    how long the token lasts, in seconds
 * @param renewable        whether the token can be renewed
 * @param mfaRequirement   set when the login needs multi-factor validation before it issues a token
 */
public record VaultResponseAuth(
        StaticVaultToken clientToken,
        String accessor,
        List<String> policies,
        List<String> tokenPolicies,
        List<String> identityPolicies,
        Map<String, String> metadata,
        boolean orphan,
        String entityId,
        long leaseDuration,
        boolean renewable,
        VaultMfaRequirement mfaRequirement) {
}
