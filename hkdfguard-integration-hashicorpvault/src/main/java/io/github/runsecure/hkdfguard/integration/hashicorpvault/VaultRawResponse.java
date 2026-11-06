package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.io.IOException;
import java.io.InputStream;
import java.net.http.HttpHeaders;

/**
 * Vault's response as it is, from {@link VaultClient#readRawAsync}: not parsed, not checked for an
 * error status, its body a stream to read and close. Unlike java.net.http's HttpResponse, it gives
 * no way back to the request, which carried the token.
 *
 * @param statusCode the status Vault answered with
 * @param headers    the response's headers
 * @param body       the response's body; close it, or this, once read
 */
public record VaultRawResponse(int statusCode, HttpHeaders headers, InputStream body) implements AutoCloseable {
    /** Closes the body. */
    @Override
    public void close() throws IOException {
        body.close();
    }
}
