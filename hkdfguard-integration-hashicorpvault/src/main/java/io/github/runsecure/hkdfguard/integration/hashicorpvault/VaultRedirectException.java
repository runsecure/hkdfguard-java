package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.io.Serial;
import java.net.URI;

/**
 * Vault answered a {@link VaultClient} request with a redirect (301, 302 or 307) the client
 * wouldn't follow: redirects are off ({@link VaultClientOptions#followRedirects()}), it was the
 * request's second, it would go from https to http, or its location couldn't be read.
 * vault-client-go's RedirectError.
 */
public final class VaultRedirectException extends VaultRequestException {
    @Serial
    private static final long serialVersionUID = 1L;

    private final String reason;
    private final URI redirectLocation;
    private final String requestMethod;
    private final URI requestUri;

    VaultRedirectException(int statusCode, String reason, URI redirectLocation, String requestMethod, URI requestUri) {
        super(statusCode + ": redirect error: " + reason, statusCode);
        this.reason = reason;
        this.redirectLocation = redirectLocation;
        this.requestMethod = requestMethod;
        this.requestUri = requestUri;
    }

    /** Why the redirect wasn't followed. */
    public String reason() {
        return reason;
    }

    /** Where the redirect pointed, if that could be read; null otherwise. */
    public URI redirectLocation() {
        return redirectLocation;
    }

    /** The method of the redirected request. */
    public String requestMethod() {
        return requestMethod;
    }

    /** The URI of the redirected request. */
    public URI requestUri() {
        return requestUri;
    }
}
