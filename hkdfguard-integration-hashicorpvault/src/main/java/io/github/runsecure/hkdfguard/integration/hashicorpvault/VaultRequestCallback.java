package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.net.http.HttpRequest;

/**
 * Called with each attempt's request before a {@link VaultClient} sends it, to add headers to it -
 * {@link VaultReplication#requireReplicationStates}, say. The request carries the client's headers
 * already, but not the token, which is added after every callback.
 */
@FunctionalInterface
public interface VaultRequestCallback {
    void onRequest(HttpRequest.Builder request);
}
