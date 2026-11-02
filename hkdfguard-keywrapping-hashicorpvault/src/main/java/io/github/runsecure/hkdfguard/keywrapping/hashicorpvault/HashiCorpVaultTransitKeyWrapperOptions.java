package io.github.runsecure.hkdfguard.keywrapping.hashicorpvault;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Objects;

/**
 * Which transit secrets engine a {@link HashiCorpVaultTransitKeyWrapperImpl} calls, and how it
 * connects. Immutable: build one with {@link #builder()}. The values are checked by the wrapper's
 * constructor, not here, so an options object can be built up in any order.
 */
public final class HashiCorpVaultTransitKeyWrapperOptions {
    /** The fewest retries {@link #retryCount()} allows. */
    public static final int MIN_RETRY_COUNT = 3;

    /** The most retries {@link #retryCount()} allows. */
    public static final int MAX_RETRY_COUNT = 10;

    /** The longest wait between retries, before the random 0-100 ms each adds. */
    public static final Duration MAX_RETRY_DELAY = Duration.ofSeconds(10);

    private final String mountPath;
    private final String namespace;
    private final Duration timeout;
    private final int retryCount;
    private final Duration retryDelay;
    private final HttpClient httpClient;
    private final boolean allowRedirects;

    private HashiCorpVaultTransitKeyWrapperOptions(Builder builder) {
        mountPath = builder.mountPath;
        namespace = builder.namespace;
        timeout = builder.timeout;
        retryCount = builder.retryCount;
        retryDelay = builder.retryDelay;
        httpClient = builder.httpClient;
        allowRedirects = builder.allowRedirects;
    }

    /** A builder holding the defaults. */
    public static Builder builder() {
        return new Builder();
    }

    /** A builder holding these options, to change some of them. */
    public Builder toBuilder() {
        return new Builder()
                .mountPath(mountPath)
                .namespace(namespace)
                .timeout(timeout)
                .retryCount(retryCount)
                .retryDelay(retryDelay)
                .httpClient(httpClient)
                .allowRedirects(allowRedirects);
    }

    /** Where the transit secrets engine is mounted, e.g. "transit" (the default) or "transit/team-a". */
    public String mountPath() {
        return mountPath;
    }

    /**
     * The Vault Enterprise namespace every request is made in, e.g. "team-a/prod"; null (the
     * default) for the root namespace. Sent as X-Vault-Namespace, as VAULT_NAMESPACE is.
     */
    public String namespace() {
        return namespace;
    }

    /**
     * How long one attempt may take: getting the token, or one request and Vault's whole response.
     * Default 30 seconds. A call that keeps failing transiently makes up to {@link #retryCount()} +
     * 1 attempts, with the waits between them.
     */
    public Duration timeout() {
        return timeout;
    }

    /**
     * How many times a request that failed transiently is retried: one that got no answer
     * (connection refused or reset, DNS), lost its connection mid-response, timed out, or was
     * answered 429 or a 5xx other than 501 (Vault answers 503 while sealed or electing a leader).
     * Anything else - 400 for a ciphertext that doesn't authenticate, 403, a token source's failure,
     * the caller's cancellation - isn't retried. Every transit call this wrapper makes is safe to
     * repeat. {@link #MIN_RETRY_COUNT}-{@link #MAX_RETRY_COUNT}; default 3.
     */
    public int retryCount() {
        return retryCount;
    }

    /**
     * The wait before the first retry, doubling before each retry after it, up to
     * {@link #MAX_RETRY_DELAY}. Every wait also adds a random 0-100 ms, so many clients
     * reconnecting at once don't all retry together. Zero to {@link #MAX_RETRY_DELAY}; default
     * 200 ms.
     */
    public Duration retryDelay() {
        return retryDelay;
    }

    /**
     * Sends every request, e.g. a client whose SSLContext trusts a private CA, or that goes through
     * a proxy. Not closed by the wrapper. Null (the default) for the wrapper's own client, which
     * follows no redirects, trusts the JDK's default trust store, and is closed with the wrapper.
     * <p>
     * A client that follows redirects ({@link HttpClient#followRedirects()} other than
     * {@link HttpClient.Redirect#NEVER}, as HttpClient.newHttpClient() is not) is refused unless
     * {@link #allowRedirects()} is set: following a redirect, even to another host, java.net.http
     * drops only Authorization, Cookie, Origin, Referer and Host, so X-Vault-Token - and the DEK in
     * an encrypt request's body - would go wherever the redirect points.
     */
    public HttpClient httpClient() {
        return httpClient;
    }

    /**
     * Accepts an {@link #httpClient()} that follows redirects, sending the Vault token along to
     * every redirect target. Set it only when every address a redirect could lead to may see the
     * token. Default false.
     */
    public boolean allowRedirects() {
        return allowRedirects;
    }

    /** Builds a {@link HashiCorpVaultTransitKeyWrapperOptions}; every value starts at its default. */
    public static final class Builder {
        private String mountPath = "transit";
        private String namespace;
        private Duration timeout = Duration.ofSeconds(30);
        private int retryCount = MIN_RETRY_COUNT;
        private Duration retryDelay = Duration.ofMillis(200);
        private HttpClient httpClient;
        private boolean allowRedirects;

        private Builder() {
        }

        /** See {@link HashiCorpVaultTransitKeyWrapperOptions#mountPath()}. */
        public Builder mountPath(String mountPath) {
            this.mountPath = mountPath;
            return this;
        }

        /** See {@link HashiCorpVaultTransitKeyWrapperOptions#namespace()}; null for the root namespace. */
        public Builder namespace(String namespace) {
            this.namespace = namespace;
            return this;
        }

        /**
         * See {@link HashiCorpVaultTransitKeyWrapperOptions#timeout()}.
         *
         * @throws NullPointerException timeout is null
         */
        public Builder timeout(Duration timeout) {
            this.timeout = Objects.requireNonNull(timeout, "timeout");
            return this;
        }

        /** See {@link HashiCorpVaultTransitKeyWrapperOptions#retryCount()}. */
        public Builder retryCount(int retryCount) {
            this.retryCount = retryCount;
            return this;
        }

        /**
         * See {@link HashiCorpVaultTransitKeyWrapperOptions#retryDelay()}.
         *
         * @throws NullPointerException retryDelay is null
         */
        public Builder retryDelay(Duration retryDelay) {
            this.retryDelay = Objects.requireNonNull(retryDelay, "retryDelay");
            return this;
        }

        /** See {@link HashiCorpVaultTransitKeyWrapperOptions#httpClient()}; null for the wrapper's own. */
        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        /** See {@link HashiCorpVaultTransitKeyWrapperOptions#allowRedirects()}. */
        public Builder allowRedirects(boolean allowRedirects) {
            this.allowRedirects = allowRedirects;
            return this;
        }

        public HashiCorpVaultTransitKeyWrapperOptions build() {
            return new HashiCorpVaultTransitKeyWrapperOptions(this);
        }
    }
}
