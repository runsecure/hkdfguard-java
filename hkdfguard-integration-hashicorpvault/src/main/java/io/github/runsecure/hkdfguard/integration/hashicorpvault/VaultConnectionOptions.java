package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Objects;

/**
 * How a HashiCorp Vault secret cache, transit key wrapper or pipeline writer connects to Vault: the
 * namespace, timeout, retries, HTTP client and TLS every one of them shares. Each one's options
 * extend this with what it reads or calls. Immutable; the values are checked by the constructor of
 * the client the options are given to, not here, so an options object can be built up in any order.
 */
public abstract class VaultConnectionOptions {
    /** The fewest retries {@link #retryCount()} allows. */
    public static final int MIN_RETRY_COUNT = VaultHttp.MIN_RETRY_COUNT;

    /** The most retries {@link #retryCount()} allows. */
    public static final int MAX_RETRY_COUNT = VaultHttp.MAX_RETRY_COUNT;

    /** The longest wait between retries, before the random 0-100 ms each adds. */
    public static final Duration MAX_RETRY_DELAY = VaultHttp.MAX_RETRY_DELAY;

    private final String namespace;
    private final Duration timeout;
    private final int retryCount;
    private final Duration retryDelay;
    private final HttpClient httpClient;
    private final boolean allowRedirects;
    private final VaultTlsOptions tls;

    /** Takes the connection values from {@code builder}. */
    protected VaultConnectionOptions(Builder<?> builder) {
        namespace = builder.namespace;
        timeout = builder.timeout;
        retryCount = builder.retryCount;
        retryDelay = builder.retryDelay;
        httpClient = builder.httpClient;
        allowRedirects = builder.allowRedirects;
        tls = builder.tls;
    }

    /** Sets {@code builder}'s connection values to these options' and returns it, for toBuilder. */
    protected final <B extends Builder<B>> B copyConnectionTo(B builder) {
        return builder
                .namespace(namespace)
                .timeout(timeout)
                .retryCount(retryCount)
                .retryDelay(retryDelay)
                .httpClient(httpClient)
                .allowRedirects(allowRedirects)
                .tls(tls);
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
     * Default 30 seconds. A request that keeps failing transiently makes up to {@link #retryCount()}
     * + 1 attempts, with the waits between them.
     */
    public Duration timeout() {
        return timeout;
    }

    /**
     * How many times a request that failed transiently is retried: one that got no answer
     * (connection refused or reset, DNS), lost its connection mid-response, timed out, or was
     * answered 429 or a 5xx other than 501 (Vault answers 503 while sealed or electing a leader).
     * Anything else - 403, a 404 naming an error, the token's source failing, the caller's
     * cancellation - isn't retried. {@link #MIN_RETRY_COUNT}-{@link #MAX_RETRY_COUNT}; default 3.
     */
    public int retryCount() {
        return retryCount;
    }

    /**
     * The wait before the first retry, doubling before each retry after it, up to
     * {@link #MAX_RETRY_DELAY}. Every wait also adds a random 0-100 ms, so many clients
     * reconnecting at once - after a network outage, say - don't all retry together. Zero to
     * {@link #MAX_RETRY_DELAY}; default 200 ms.
     */
    public Duration retryDelay() {
        return retryDelay;
    }

    /**
     * Sends every request, e.g. a client whose SSLContext trusts a private CA, or that goes through
     * a proxy. Never closed by the Vault client it is given to. Null (the default) for that client's
     * own, which follows no redirects, trusts the JDK's default trust store, and is closed with it.
     * <p>
     * A client that follows redirects ({@link HttpClient#followRedirects()} other than
     * {@link HttpClient.Redirect#NEVER}, as HttpClient.newHttpClient() is not) is refused unless
     * {@link #allowRedirects()} is set: following a redirect, even to another host, java.net.http
     * drops only Authorization, Cookie, Origin, Referer and Host, so X-Vault-Token - and whatever
     * secret a request's body holds - would go wherever the redirect points.
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

    /**
     * Which CA certificates Vault's certificate must chain to, and which client certificate the
     * Vault client's own HttpClient presents to a Vault requiring mutual TLS (see
     * {@link VaultTlsOptions}). Read when that client is created. Null (the default) for the JDK's
     * default trust store and no client certificate. Can't be combined with {@link #httpClient()},
     * whose own SSLContext decides.
     */
    public VaultTlsOptions tls() {
        return tls;
    }

    /**
     * The connection half of an options builder; every value starts at its default.
     *
     * @param <B> the builder extending this one, which every setter returns
     */
    public abstract static class Builder<B extends Builder<B>> {
        private String namespace;
        private Duration timeout = Duration.ofSeconds(30);
        private int retryCount = MIN_RETRY_COUNT;
        private Duration retryDelay = Duration.ofMillis(200);
        private HttpClient httpClient;
        private boolean allowRedirects;
        private VaultTlsOptions tls;

        /** A builder holding the defaults. */
        protected Builder() {
        }

        /** This builder, as the type its setters return. */
        protected abstract B self();

        /** See {@link VaultConnectionOptions#namespace()}; null for the root namespace. */
        public B namespace(String namespace) {
            this.namespace = namespace;
            return self();
        }

        /**
         * See {@link VaultConnectionOptions#timeout()}.
         *
         * @throws NullPointerException timeout is null
         */
        public B timeout(Duration timeout) {
            this.timeout = Objects.requireNonNull(timeout, "timeout");
            return self();
        }

        /** See {@link VaultConnectionOptions#retryCount()}. */
        public B retryCount(int retryCount) {
            this.retryCount = retryCount;
            return self();
        }

        /**
         * See {@link VaultConnectionOptions#retryDelay()}.
         *
         * @throws NullPointerException retryDelay is null
         */
        public B retryDelay(Duration retryDelay) {
            this.retryDelay = Objects.requireNonNull(retryDelay, "retryDelay");
            return self();
        }

        /** See {@link VaultConnectionOptions#httpClient()}; null for the Vault client's own. */
        public B httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return self();
        }

        /** See {@link VaultConnectionOptions#allowRedirects()}. */
        public B allowRedirects(boolean allowRedirects) {
            this.allowRedirects = allowRedirects;
            return self();
        }

        /** See {@link VaultConnectionOptions#tls()}; null for the JDK's defaults. */
        public B tls(VaultTlsOptions tls) {
            this.tls = tls;
            return self();
        }
    }
}
