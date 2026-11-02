package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.net.URI;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;

/**
 * The headers and callbacks a client adds to every request. Immutable: the client swaps in a new one
 * when a setting changes, so a request in flight keeps the settings it started with.
 */
record RequestModifiers(
        String userAgent,
        VaultTokenProvider token,
        String namespace,
        List<String> mfaCredentials,
        Duration responseWrappingTtl,
        ReplicationForwardingMode replicationForwardingMode,
        Map<String, List<String>> customHeaders,
        List<VaultRequestCallback> requestCallbacks,
        List<VaultResponseCallback> responseCallbacks) {

    static RequestModifiers initial(String userAgent, VaultTokenProvider token, String namespace) {
        return new RequestModifiers(userAgent, token, namespace, List.of(), Duration.ZERO, ReplicationForwardingMode.NONE, Map.of(), List.of(),
                List.of());
    }

    RequestModifiers withToken(VaultTokenProvider value) {
        return new RequestModifiers(userAgent, value, namespace, mfaCredentials, responseWrappingTtl, replicationForwardingMode, customHeaders,
                requestCallbacks, responseCallbacks);
    }

    RequestModifiers withNamespace(String value) {
        return new RequestModifiers(userAgent, token, value, mfaCredentials, responseWrappingTtl, replicationForwardingMode, customHeaders,
                requestCallbacks, responseCallbacks);
    }

    RequestModifiers withMfaCredentials(List<String> value) {
        return new RequestModifiers(userAgent, token, namespace, value, responseWrappingTtl, replicationForwardingMode, customHeaders,
                requestCallbacks, responseCallbacks);
    }

    RequestModifiers withResponseWrappingTtl(Duration value) {
        return new RequestModifiers(userAgent, token, namespace, mfaCredentials, value, replicationForwardingMode, customHeaders,
                requestCallbacks, responseCallbacks);
    }

    RequestModifiers withReplicationForwardingMode(ReplicationForwardingMode value) {
        return new RequestModifiers(userAgent, token, namespace, mfaCredentials, responseWrappingTtl, value, customHeaders,
                requestCallbacks, responseCallbacks);
    }

    RequestModifiers withCustomHeaders(Map<String, List<String>> value) {
        return new RequestModifiers(userAgent, token, namespace, mfaCredentials, responseWrappingTtl, replicationForwardingMode, value,
                requestCallbacks, responseCallbacks);
    }

    RequestModifiers withRequestCallbacks(List<VaultRequestCallback> value) {
        return new RequestModifiers(userAgent, token, namespace, mfaCredentials, responseWrappingTtl, replicationForwardingMode, customHeaders,
                value, responseCallbacks);
    }

    RequestModifiers withResponseCallbacks(List<VaultResponseCallback> value) {
        return new RequestModifiers(userAgent, token, namespace, mfaCredentials, responseWrappingTtl, replicationForwardingMode, customHeaders,
                requestCallbacks, value);
    }

    /**
     * These with options' over them: options' single values win, its lists are appended, and its
     * headers replace these headers of the same name.
     *
     * @throws IllegalArgumentException options holds a namespace, MFA credential or header that can't be sent
     */
    RequestModifiers merge(VaultRequestOptions options) {
        if (options == null)
            return this;

        var ns = options.namespace();
        if (ns != null && !ns.isEmpty() && !VaultClient.isValidNamespace(ns))
            throw new IllegalArgumentException("The namespace '" + ns + "' contains non-printable characters.");
        validateMfaCredentials(options.mfaCredentials());
        validateCustomHeaders(options.customHeaders());

        var headers = customHeaders;
        if (!options.customHeaders().isEmpty()) {
            var merged = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
            merged.putAll(customHeaders);
            merged.putAll(options.customHeaders());
            headers = Collections.unmodifiableMap(merged);
        }

        var ttl = options.responseWrappingTtl();
        return new RequestModifiers(
                userAgent,
                options.token() != null ? options.token() : token,
                ns == null || ns.isEmpty() ? namespace : ns,
                concat(mfaCredentials, options.mfaCredentials()),
                ttl != null && !ttl.isZero() ? ttl : responseWrappingTtl,
                options.replicationForwardingMode() != ReplicationForwardingMode.NONE ? options.replicationForwardingMode() : replicationForwardingMode,
                headers,
                concat(requestCallbacks, options.requestCallbacks()),
                concat(responseCallbacks, options.responseCallbacks()));
    }

    /** @throws IllegalArgumentException a credential can't go in a header */
    static void validateMfaCredentials(List<String> credentials) {
        for (var credential : credentials) {
            if (credential == null || credential.isEmpty() || !VaultClient.isValidNamespace(credential))
                throw new IllegalArgumentException("An MFA credential must be non-empty printable ASCII.");
        }
    }

    /** @throws IllegalArgumentException a header is named X-Vault-*, has no name, or can't be sent */
    static void validateCustomHeaders(Map<String, List<String>> headers) {
        if (headers == null)
            return;

        var probe = HttpRequest.newBuilder(URI.create("http://localhost/"));
        for (var header : headers.entrySet()) {
            var name = header.getKey();
            if (name == null || name.isBlank())
                throw new IllegalArgumentException("A custom header must have a name.");
            if (name.toLowerCase(Locale.ROOT).startsWith("x-vault-"))
                throw new IllegalArgumentException("The custom header '" + name + "' isn't allowed: the 'X-Vault-' prefix is for the client's own use.");
            // Refused now rather than on every request: a restricted name (Host, Content-Length...)
            // or a value java.net.http won't send.
            for (var value : header.getValue())
                probe.header(name, value);
        }
    }

    /** headers, copied: unmodifiable, its names case-insensitive. */
    static Map<String, List<String>> copyHeaders(Map<String, List<String>> headers) {
        if (headers == null || headers.isEmpty())
            return Map.of();

        var copy = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
        for (var header : headers.entrySet())
            copy.put(header.getKey(), List.copyOf(header.getValue()));
        return Collections.unmodifiableMap(copy);
    }

    private static <T> List<T> concat(List<T> first, List<T> second) {
        if (second.isEmpty())
            return first;
        if (first.isEmpty())
            return second;

        var all = new ArrayList<T>(first);
        all.addAll(second);
        return List.copyOf(all);
    }
}
