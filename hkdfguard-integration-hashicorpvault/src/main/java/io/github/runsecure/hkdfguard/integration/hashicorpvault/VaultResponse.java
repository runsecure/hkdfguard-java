package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.util.List;

/**
 * What Vault answers most requests with. A response without a "data", "auth" or "wrap_info" member
 * - sys/health, sys/leader and sys/seal-status, for instance - is read whole into {@link #data()}.
 *
 * @param requestId     the id of the request this answers
 * @param leaseId       the lease on a dynamic secret, for renewing or revoking it
 * @param leaseDuration how long the lease lasts, in seconds
 * @param renewable     whether the lease can be renewed
 * @param data          the response's contents, whose shape depends on the endpoint: a generated
 *                      model, or a map of JSON values
 * @param warnings      things Vault wants noticed that didn't fail the request
 * @param auth          the token a login issued, and about it; null for anything but a login
 * @param wrapInfo      the wrapping token, when the response was wrapped
 *                      ({@link VaultRequestOptions#responseWrappingTtl()})
 * @param <T>           what data holds
 */
public record VaultResponse<T>(
        String requestId,
        String leaseId,
        long leaseDuration,
        boolean renewable,
        T data,
        List<String> warnings,
        VaultResponseAuth auth,
        VaultResponseWrapInfo wrapInfo) {
}
