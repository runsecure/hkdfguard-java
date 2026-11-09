package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;

/**
 * How a {@link VaultClient} reaches Vault: vault-client-go's ClientConfiguration. Immutable: build
 * one with {@link #builder()}, or read one from the environment with {@link #fromEnvironment}. The
 * values are checked by the client's constructor, not here.
 */
public final class VaultClientOptions {
    /** The address used when none is set: a local Vault server or agent. */
    public static final URI DEFAULT_ADDRESS = URI.create("https://127.0.0.1:8200");

    private final URI address;
    private final boolean allowUnencryptedHttp;
    private final HttpClient httpClient;
    private final Duration requestTimeout;
    private final VaultTlsOptions tls;
    private final VaultRetryOptions retry;
    private final VaultRateLimiter rateLimiter;
    private final boolean enforceReadYourWritesConsistency;
    private final boolean followRedirects;
    private final List<URI> redirectOrigins;
    private final VaultTokenProvider token;
    private final String namespace;

    private VaultClientOptions(Builder builder) {
        address = builder.address;
        allowUnencryptedHttp = builder.allowUnencryptedHttp;
        httpClient = builder.httpClient;
        requestTimeout = builder.requestTimeout;
        tls = builder.tls;
        retry = builder.retry;
        rateLimiter = builder.rateLimiter;
        enforceReadYourWritesConsistency = builder.enforceReadYourWritesConsistency;
        followRedirects = builder.followRedirects;
        redirectOrigins = builder.redirectOrigins;
        token = builder.token;
        namespace = builder.namespace;
    }

    /** A builder holding the defaults. */
    public static Builder builder() {
        return new Builder();
    }

    /** A builder holding these options, to change some of them. */
    public Builder toBuilder() {
        return new Builder()
                .address(address)
                .allowUnencryptedHttp(allowUnencryptedHttp)
                .httpClient(httpClient)
                .requestTimeout(requestTimeout)
                .tls(tls)
                .retry(retry)
                .rateLimiter(rateLimiter)
                .enforceReadYourWritesConsistency(enforceReadYourWritesConsistency)
                .followRedirects(followRedirects)
                .redirectOrigins(redirectOrigins)
                .token(token)
                .namespace(namespace);
    }

    /**
     * Vault's address, scheme://host:port - VAULT_ADDR. https; http only on a loopback address (a
     * local agent or dev server) unless {@link #allowUnencryptedHttp()} is set, since every request
     * carries a token. A path, if any, is kept as a prefix (Vault behind a reverse proxy). Unix domain
     * sockets (unix://), which vault-client-go also reaches, aren't: java.net.http can't connect to
     * one. Default {@link #DEFAULT_ADDRESS}.
     */
    public URI address() {
        return address;
    }

    /** Allows an http address that isn't loopback, and redirects to one. Off: the token would cross the network in the clear. */
    public boolean allowUnencryptedHttp() {
        return allowUnencryptedHttp;
    }

    /**
     * Sends every request, e.g. one going through a proxy; not closed by the client. Null (the
     * default) for the client's own: TLS 1.2 or later, no automatic redirects, configured by
     * {@link #tls()}, closed with the client. A supplied client must not follow redirects itself -
     * java.net.http would carry X-Vault-Token along - and can't be combined with {@link #tls()}: give
     * it its own SSLContext instead.
     */
    public HttpClient httpClient() {
        return httpClient;
    }

    /**
     * How long each request may take, its token, retries and redirect included, unless the caller
     * cancels it first - VAULT_CLIENT_TIMEOUT. Zero for none. Not applied to
     * {@link VaultClient#readRawAsync}. Default 60 seconds.
     */
    public Duration requestTimeout() {
        return requestTimeout;
    }

    /** Which certificates to trust and to present. */
    public VaultTlsOptions tls() {
        return tls;
    }

    /** When and how often a failed request is retried. */
    public VaultRetryOptions retry() {
        return retry;
    }

    /** Limits how often requests are sent - VAULT_RATE_LIMIT. Null for no limit. One limiter can be shared by several clients. */
    public VaultRateLimiter rateLimiter() {
        return rateLimiter;
    }

    /**
     * Sends the replication states seen in earlier responses with every request, so a performance
     * standby that hasn't caught up forwards it to the active node: read-your-writes consistency
     * across a cluster, at a cost on every request. Requires Vault Enterprise; see
     * https://developer.hashicorp.com/vault/docs/enterprise/consistency#vault-1-7-mitigations.
     */
    public boolean enforceReadYourWritesConsistency() {
        return enforceReadYourWritesConsistency;
    }

    /**
     * Follows one redirect (301, 302 or 307) per request, never from https to http, and only to the
     * address's own origin or one {@link #redirectOrigins()} lists. Off: a redirect fails with
     * {@link VaultRedirectException}, since it would carry the token wherever it points. Some calls
     * need it - raft operations sent to a standby are redirected to the active node, at that node's
     * own address, so list every node's address in redirectOrigins.
     */
    public boolean followRedirects() {
        return followRedirects;
    }

    /**
     * The origins - scheme://host:port, compared without regard to case, with the scheme's default
     * port when none is given - a followed redirect may lead to besides the address's own: the other
     * nodes of the Vault cluster. A redirect anywhere else fails with {@link VaultRedirectException},
     * because it would carry the token there. Each must be https, or http where the address may be.
     * Default none.
     */
    public List<URI> redirectOrigins() {
        return redirectOrigins;
    }

    /** The token every request is made with unless the request sets its own; null for none until {@link VaultClient#setToken(VaultTokenProvider)}. */
    public VaultTokenProvider token() {
        return token;
    }

    /** The namespace every request is made in unless the request sets its own - VAULT_NAMESPACE. Vault Enterprise. */
    public String namespace() {
        return namespace;
    }

    /**
     * Options from the environment variables vault-client-go reads, over the defaults:
     * <ul>
     * <li>VAULT_ADDR, VAULT_AGENT_ADDR - {@link #address()} (VAULT_AGENT_ADDR wins if both are set)</li>
     * <li>VAULT_CLIENT_TIMEOUT - {@link #requestTimeout()}, a Go duration such as 30s</li>
     * <li>VAULT_RATE_LIMIT - {@link #rateLimiter()}, rate[:burst] in requests per second</li>
     * <li>VAULT_DISABLE_REDIRECTS - true turns {@link #followRedirects()} off; false leaves it as it is</li>
     * <li>VAULT_TOKEN - {@link #token()}, protected with tokenProtector; ignored without one</li>
     * <li>VAULT_NAMESPACE - {@link #namespace()}</li>
     * <li>VAULT_SKIP_VERIFY, VAULT_CACERT, VAULT_CACERT_BYTES, VAULT_CAPATH, VAULT_CLIENT_CERT,
     * VAULT_CLIENT_KEY, VAULT_TLS_SERVER_NAME - {@link #tls()}</li>
     * <li>VAULT_RETRY_WAIT_MIN, VAULT_RETRY_WAIT_MAX, VAULT_MAX_RETRIES - {@link #retry()}</li>
     * </ul>
     *
     * @param tokenProtector the protector the client will be given, to protect VAULT_TOKEN with;
     *                       null to ignore VAULT_TOKEN
     * @throws IllegalArgumentException a variable is set to a value that isn't one
     */
    public static VaultClientOptions fromEnvironment(DataProtector tokenProtector) {
        return fromEnvironment(System::getenv, tokenProtector);
    }

    static VaultClientOptions fromEnvironment(Function<String, String> variable, DataProtector tokenProtector) {
        var options = builder();

        // Later variables win, as in vault-client-go.
        for (var name : new String[] {"VAULT_ADDR", "VAULT_AGENT_ADDR"}) {
            var address = value(variable, name);
            if (address != null)
                options.address(parse(name, address, VaultClientOptions::parseAddress));
        }

        var timeout = value(variable, "VAULT_CLIENT_TIMEOUT");
        if (timeout != null)
            options.requestTimeout(parse("VAULT_CLIENT_TIMEOUT", timeout, GoDuration::parse));
        var rateLimit = value(variable, "VAULT_RATE_LIMIT");
        if (rateLimit != null)
            options.rateLimiter(parse("VAULT_RATE_LIMIT", rateLimit, VaultClientOptions::parseRateLimit));
        var disableRedirects = value(variable, "VAULT_DISABLE_REDIRECTS");
        if (disableRedirects != null && parse("VAULT_DISABLE_REDIRECTS", disableRedirects, VaultClientOptions::parseBool))
            options.followRedirects(false);
        var namespace = value(variable, "VAULT_NAMESPACE");
        if (namespace != null) {
            if (!VaultClient.isValidNamespace(namespace))
                throw new IllegalArgumentException("VAULT_NAMESPACE contains non-printable characters.");
            options.namespace(namespace);
        }

        var token = tokenProtector == null ? null : value(variable, "VAULT_TOKEN");
        if (token != null) {
            if (!VaultHttp.isValidToken(token))
                throw new IllegalArgumentException("VAULT_TOKEN isn't a token: printable ASCII, with no spaces.");
            options.token(StaticVaultToken.protect(tokenProtector, token));
        }

        var tls = VaultTlsOptions.builder();
        var skipVerify = value(variable, "VAULT_SKIP_VERIFY");
        if (skipVerify != null)
            tls.insecureSkipVerify(parse("VAULT_SKIP_VERIFY", skipVerify, VaultClientOptions::parseBool));
        var caCert = value(variable, "VAULT_CACERT");
        if (caCert != null)
            tls.serverCertificateFile(Path.of(caCert));
        var caBytes = value(variable, "VAULT_CACERT_BYTES");
        if (caBytes != null)
            tls.serverCertificatePem(caBytes.getBytes(StandardCharsets.UTF_8));
        var caPath = value(variable, "VAULT_CAPATH");
        if (caPath != null)
            tls.serverCertificateDirectory(Path.of(caPath));
        var clientCert = value(variable, "VAULT_CLIENT_CERT");
        if (clientCert != null)
            tls.clientCertificateFile(Path.of(clientCert));
        var clientKey = value(variable, "VAULT_CLIENT_KEY");
        if (clientKey != null)
            tls.clientCertificateKeyFile(Path.of(clientKey));
        var serverName = value(variable, "VAULT_TLS_SERVER_NAME");
        if (serverName != null)
            tls.serverName(serverName);
        options.tls(tls.build());

        var retry = VaultRetryOptions.builder();
        var waitMin = value(variable, "VAULT_RETRY_WAIT_MIN");
        if (waitMin != null)
            retry.retryWaitMin(parse("VAULT_RETRY_WAIT_MIN", waitMin, GoDuration::parse));
        var waitMax = value(variable, "VAULT_RETRY_WAIT_MAX");
        if (waitMax != null)
            retry.retryWaitMax(parse("VAULT_RETRY_WAIT_MAX", waitMax, GoDuration::parse));
        var maxRetries = value(variable, "VAULT_MAX_RETRIES");
        if (maxRetries != null)
            retry.retryMax(parse("VAULT_MAX_RETRIES", maxRetries, Integer::parseInt));
        options.retry(retry.build());

        return options.build();
    }

    // An unset variable and an empty one are the same, as in vault-client-go.
    private static String value(Function<String, String> variable, String name) {
        var value = variable.apply(name);
        return value == null || value.isEmpty() ? null : value;
    }

    private static <T> T parse(String name, String value, Function<String, T> parse) {
        try {
            return parse.apply(value);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Configuration error: could not convert the " + name + " environment variable's value '"
                    + value + "': " + e.getMessage(), e);
        }
    }

    private static URI parseAddress(String address) {
        var uri = URI.create(address);
        if (!uri.isAbsolute())
            throw new IllegalArgumentException("Not an absolute URI.");
        return uri;
    }

    // strconv.ParseBool's spellings.
    private static boolean parseBool(String value) {
        return switch (value) {
            case "1", "t", "T", "TRUE", "true", "True" -> true;
            case "0", "f", "F", "FALSE", "false", "False" -> false;
            default -> throw new IllegalArgumentException("Expected a boolean: 1, t, T, TRUE, true, True, 0, f, F, FALSE, false or False.");
        };
    }

    // "rate:burst", or "rate" with a burst of the rate rounded down (at least 1).
    private static VaultRateLimiter parseRateLimit(String value) {
        var colon = value.indexOf(':');
        if (colon >= 0)
            return new VaultRateLimiter(Double.parseDouble(value.substring(0, colon)), Integer.parseInt(value.substring(colon + 1)));

        var rate = Double.parseDouble(value);
        return new VaultRateLimiter(rate, (int) Math.max(1, Math.min(rate, Integer.MAX_VALUE)));
    }

    /** Builds {@link VaultClientOptions}; every value starts at its default. */
    public static final class Builder {
        private URI address = DEFAULT_ADDRESS;
        private boolean allowUnencryptedHttp;
        private HttpClient httpClient;
        private Duration requestTimeout = Duration.ofSeconds(60);
        private VaultTlsOptions tls = VaultTlsOptions.builder().build();
        private VaultRetryOptions retry = VaultRetryOptions.builder().build();
        private VaultRateLimiter rateLimiter;
        private boolean enforceReadYourWritesConsistency;
        private boolean followRedirects;
        private List<URI> redirectOrigins = List.of();
        private VaultTokenProvider token;
        private String namespace;

        private Builder() {
        }

        /** See {@link VaultClientOptions#address()}. */
        public Builder address(URI address) {
            this.address = Objects.requireNonNull(address, "address");
            return this;
        }

        /** See {@link VaultClientOptions#allowUnencryptedHttp()}. */
        public Builder allowUnencryptedHttp(boolean allowUnencryptedHttp) {
            this.allowUnencryptedHttp = allowUnencryptedHttp;
            return this;
        }

        /** See {@link VaultClientOptions#httpClient()}; null for the client's own. */
        public Builder httpClient(HttpClient httpClient) {
            this.httpClient = httpClient;
            return this;
        }

        /** See {@link VaultClientOptions#requestTimeout()}. */
        public Builder requestTimeout(Duration requestTimeout) {
            this.requestTimeout = Objects.requireNonNull(requestTimeout, "requestTimeout");
            return this;
        }

        /** See {@link VaultClientOptions#tls()}. */
        public Builder tls(VaultTlsOptions tls) {
            this.tls = Objects.requireNonNull(tls, "tls");
            return this;
        }

        /** See {@link VaultClientOptions#retry()}. */
        public Builder retry(VaultRetryOptions retry) {
            this.retry = Objects.requireNonNull(retry, "retry");
            return this;
        }

        /** See {@link VaultClientOptions#rateLimiter()}; null for none. */
        public Builder rateLimiter(VaultRateLimiter rateLimiter) {
            this.rateLimiter = rateLimiter;
            return this;
        }

        /** See {@link VaultClientOptions#enforceReadYourWritesConsistency()}. */
        public Builder enforceReadYourWritesConsistency(boolean enforce) {
            this.enforceReadYourWritesConsistency = enforce;
            return this;
        }

        /** See {@link VaultClientOptions#followRedirects()}. */
        public Builder followRedirects(boolean followRedirects) {
            this.followRedirects = followRedirects;
            return this;
        }

        /** See {@link VaultClientOptions#redirectOrigins()}; copied, null for none. */
        public Builder redirectOrigins(Collection<URI> redirectOrigins) {
            this.redirectOrigins = redirectOrigins == null ? List.of() : List.copyOf(redirectOrigins);
            return this;
        }

        /** See {@link VaultClientOptions#token()}; null for none. */
        public Builder token(VaultTokenProvider token) {
            this.token = token;
            return this;
        }

        /** See {@link VaultClientOptions#namespace()}; null or empty for none. */
        public Builder namespace(String namespace) {
            this.namespace = namespace;
            return this;
        }

        public VaultClientOptions build() {
            return new VaultClientOptions(this);
        }
    }
}
