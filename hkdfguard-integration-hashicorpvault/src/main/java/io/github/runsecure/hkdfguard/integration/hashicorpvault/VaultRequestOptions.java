package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Settings for one request: vault-client-go's RequestOption. They combine with the client's own
 * ({@link VaultClient#setToken(VaultTokenProvider)} and the rest) this way: a single value set here
 * wins over the client's; a list here is added to the client's; a header here replaces the client's
 * header of the same name and keeps the rest. Immutable: build one with {@link #builder()}.
 */
public final class VaultRequestOptions {
    private final VaultTokenProvider token;
    private final String namespace;
    private final List<String> mfaCredentials;
    private final Duration responseWrappingTtl;
    private final Map<String, List<String>> customHeaders;
    private final List<VaultRequestCallback> requestCallbacks;
    private final List<VaultResponseCallback> responseCallbacks;
    private final String mountPath;
    private final List<Map.Entry<String, String>> queryParameters;
    private final ReplicationForwardingMode replicationForwardingMode;

    private VaultRequestOptions(Builder builder) {
        token = builder.token;
        namespace = builder.namespace;
        mfaCredentials = List.copyOf(builder.mfaCredentials);
        responseWrappingTtl = builder.responseWrappingTtl;
        customHeaders = RequestModifiers.copyHeaders(builder.customHeaders);
        requestCallbacks = List.copyOf(builder.requestCallbacks);
        responseCallbacks = List.copyOf(builder.responseCallbacks);
        mountPath = builder.mountPath;
        queryParameters = List.copyOf(builder.queryParameters);
        replicationForwardingMode = builder.replicationForwardingMode;
    }

    /** A builder holding nothing: every setting the client's. */
    public static Builder builder() {
        return new Builder();
    }

    /** A builder holding these options, to change some of them. */
    public Builder toBuilder() {
        var builder = new Builder()
                .token(token)
                .namespace(namespace)
                .responseWrappingTtl(responseWrappingTtl)
                .customHeaders(customHeaders)
                .mountPath(mountPath)
                .replicationForwardingMode(replicationForwardingMode);
        builder.mfaCredentials.addAll(mfaCredentials);
        builder.requestCallbacks.addAll(requestCallbacks);
        builder.responseCallbacks.addAll(responseCallbacks);
        builder.queryParameters.addAll(queryParameters);
        return builder;
    }

    /** The token to make this request with, instead of the client's; null for the client's. */
    public VaultTokenProvider token() {
        return token;
    }

    /** The namespace to make this request in, instead of the client's; null or empty keeps the client's. */
    public String namespace() {
        return namespace;
    }

    /** Multi-factor credentials (X-Vault-MFA), added to the client's; see https://developer.hashicorp.com/vault/docs/auth/login-mfa. */
    public List<String> mfaCredentials() {
        return mfaCredentials;
    }

    /**
     * Asks Vault to wrap the response for this long (X-Vault-Wrap-TTL) instead of returning it: the
     * response holds only {@link VaultResponse#wrapInfo()}, for {@link VaultClient#unwrapAsync}. Null
     * or zero keeps the client's setting; see
     * https://developer.hashicorp.com/vault/docs/concepts/response-wrapping.
     */
    public Duration responseWrappingTtl() {
        return responseWrappingTtl;
    }

    /** Headers to add, over the client's; names starting X-Vault- are the client's own and refused. */
    public Map<String, List<String>> customHeaders() {
        return customHeaders;
    }

    /** Called with each attempt's request before it's sent, after the client's own callbacks. The token isn't on it yet. */
    public List<VaultRequestCallback> requestCallbacks() {
        return requestCallbacks;
    }

    /** Called once Vault has answered, after the client's own callbacks. */
    public List<VaultResponseCallback> responseCallbacks() {
        return responseCallbacks;
    }

    /**
     * Where the auth method or secrets engine is mounted, instead of its default - for the generated
     * {@link VaultClient#auth()} and {@link VaultClient#secrets()} methods; leading and trailing '/'
     * are ignored.
     */
    public String mountPath() {
        return mountPath;
    }

    /** Query parameters to add to the request; meant for the generic read, readRaw, list and delete. */
    public List<Map.Entry<String, String>> queryParameters() {
        return queryParameters;
    }

    /** Whether a performance standby forwards this request to the active node; NONE keeps the client's. */
    public ReplicationForwardingMode replicationForwardingMode() {
        return replicationForwardingMode;
    }

    /** Builds {@link VaultRequestOptions}. */
    public static final class Builder {
        private VaultTokenProvider token;
        private String namespace;
        private final List<String> mfaCredentials = new ArrayList<>();
        private Duration responseWrappingTtl;
        private Map<String, List<String>> customHeaders = Map.of();
        private final List<VaultRequestCallback> requestCallbacks = new ArrayList<>();
        private final List<VaultResponseCallback> responseCallbacks = new ArrayList<>();
        private String mountPath;
        private final List<Map.Entry<String, String>> queryParameters = new ArrayList<>();
        private ReplicationForwardingMode replicationForwardingMode = ReplicationForwardingMode.NONE;

        private Builder() {
        }

        /** See {@link VaultRequestOptions#token()}. */
        public Builder token(VaultTokenProvider token) {
            this.token = token;
            return this;
        }

        /** See {@link VaultRequestOptions#namespace()}. */
        public Builder namespace(String namespace) {
            this.namespace = namespace;
            return this;
        }

        /** Adds to {@link VaultRequestOptions#mfaCredentials()}. */
        public Builder mfaCredentials(String... credentials) {
            for (var credential : credentials)
                mfaCredentials.add(Objects.requireNonNull(credential, "credential"));
            return this;
        }

        /** See {@link VaultRequestOptions#responseWrappingTtl()}. */
        public Builder responseWrappingTtl(Duration ttl) {
            this.responseWrappingTtl = ttl;
            return this;
        }

        /** See {@link VaultRequestOptions#customHeaders()}; copied. */
        public Builder customHeaders(Map<String, List<String>> headers) {
            this.customHeaders = headers == null ? Map.of() : new LinkedHashMap<>(headers);
            return this;
        }

        /** Adds to {@link VaultRequestOptions#requestCallbacks()}. */
        public Builder requestCallbacks(VaultRequestCallback... callbacks) {
            for (var callback : callbacks)
                requestCallbacks.add(Objects.requireNonNull(callback, "callback"));
            return this;
        }

        /** Adds to {@link VaultRequestOptions#responseCallbacks()}. */
        public Builder responseCallbacks(VaultResponseCallback... callbacks) {
            for (var callback : callbacks)
                responseCallbacks.add(Objects.requireNonNull(callback, "callback"));
            return this;
        }

        /** See {@link VaultRequestOptions#mountPath()}. */
        public Builder mountPath(String mountPath) {
            this.mountPath = mountPath;
            return this;
        }

        /** Adds a query parameter; see {@link VaultRequestOptions#queryParameters()}. */
        public Builder queryParameter(String name, String value) {
            queryParameters.add(Map.entry(name, value));
            return this;
        }

        /** See {@link VaultRequestOptions#replicationForwardingMode()}. */
        public Builder replicationForwardingMode(ReplicationForwardingMode mode) {
            this.replicationForwardingMode = Objects.requireNonNull(mode, "mode");
            return this;
        }

        public VaultRequestOptions build() {
            return new VaultRequestOptions(this);
        }
    }
}
