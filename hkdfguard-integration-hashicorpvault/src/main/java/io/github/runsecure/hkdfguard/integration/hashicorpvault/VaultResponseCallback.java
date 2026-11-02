package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;

/**
 * Called once Vault has answered a {@link VaultClient} request (after any retries and redirect),
 * before its body is read - {@link VaultReplication#recordReplicationState}, say.
 */
@FunctionalInterface
public interface VaultResponseCallback {
    /**
     * @param request    the request Vault answered, without its token
     * @param statusCode the status Vault answered with
     * @param headers    the response's headers
     */
    void onResponse(HttpRequest request, int statusCode, HttpHeaders headers);
}
