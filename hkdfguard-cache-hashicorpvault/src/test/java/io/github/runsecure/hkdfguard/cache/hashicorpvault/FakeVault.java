package io.github.runsecure.hkdfguard.cache.hashicorpvault;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * A KV secrets engine behind Vault's HTTP API, served over plain http on 127.0.0.1 (which the cache
 * allows on loopback): a GET of a secret's read path with the expected token is answered as Vault
 * answers it - the secret, or 404 with an empty error list - for KV version 2 (the default) or 1. A
 * request without that token is refused with 403, as Vault refuses it. Any other request - a LIST,
 * a query, another path - is recorded in {@link #unexpectedRequests} and refused. Paths are matched
 * exactly, as Vault matches them.
 */
final class FakeVault implements AutoCloseable {
    static final String TOKEN = "hvs.CAESIFakeTokenForTests";

    /** An answer given as it is: a status, a body ("" for none) and any extra headers. */
    record Answer(int status, String body, Map<String, String> headers) {
        Answer(int status, String body) {
            this(status, body, Map.of());
        }
    }

    /** Runs inside a read before it answers: may hold it open, answer it itself, or throw to drop the connection. */
    @FunctionalInterface
    interface ReadHook {
        void run(HttpExchange exchange) throws IOException;
    }

    private final HttpServer server;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    private final String mountPath;
    private final VaultKvVersion kvVersion;
    private final String pathPrefix;
    private final Map<String, Map<String, Object>> secrets = new ConcurrentHashMap<>();
    private final Set<String> deleted = ConcurrentHashMap.newKeySet();

    private final List<String> reads = Collections.synchronizedList(new ArrayList<>());
    private final List<String> tokens = Collections.synchronizedList(new ArrayList<>());
    private final List<String> namespaces = Collections.synchronizedList(new ArrayList<>());
    private final List<String> vaultRequestHeaders = Collections.synchronizedList(new ArrayList<>());
    private final List<String> unexpectedRequests = Collections.synchronizedList(new ArrayList<>());

    /** When set, a read with the right token is answered with this. */
    volatile Answer answer;

    /** When set, runs inside every read before it answers. */
    volatile ReadHook onRead;

    FakeVault() {
        this("secret", VaultKvVersion.V2, "");
    }

    /**
     * @param pathPrefix the path /v1/ is under, for an address with a path prefix: "" or "/vault"
     */
    FakeVault(String mountPath, VaultKvVersion kvVersion, String pathPrefix) {
        this.mountPath = mountPath;
        this.kvVersion = kvVersion;
        this.pathPrefix = pathPrefix;
        try {
            server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        server.setExecutor(executor);
        server.createContext("/", this::handle);
        server.start();
    }

    /** Vault's address, with the path prefix if any, as VAULT_ADDR would hold it. */
    URI address() {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + pathPrefix + "/");
    }

    /** The address of the read path of the secret at path, for a request made without the cache. */
    URI readUri(String path) {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + readPrefix() + path);
    }

    void setData(String path, Map<String, Object> data) {
        secrets.put(path, data);
    }

    void set(String path, String value) {
        setData(path, Map.of("value", value));
    }

    /** A KV version 2 secret whose latest version is deleted: Vault answers 404 with its metadata. */
    void setDeleted(String path) {
        deleted.add(path);
    }

    /** Every secret path read, in order. */
    List<String> reads() {
        return snapshot(reads);
    }

    /** The X-Vault-Token of every read, in order; "" where it had none. */
    List<String> tokens() {
        return snapshot(tokens);
    }

    /** The X-Vault-Namespace of every read, in order; "(none)" where it had none. */
    List<String> namespaces() {
        return snapshot(namespaces);
    }

    /** The X-Vault-Request header of every read, in order; "(none)" where it had none. */
    List<String> vaultRequestHeaders() {
        return snapshot(vaultRequestHeaders);
    }

    /** Every other request, as "METHOD path?query". */
    List<String> unexpectedRequests() {
        return snapshot(unexpectedRequests);
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }

    private String readPrefix() {
        return pathPrefix + "/v1/" + mountPath + "/" + (kvVersion == VaultKvVersion.V2 ? "data/" : "");
    }

    private void handle(HttpExchange exchange) throws IOException {
        var uri = exchange.getRequestURI();
        var readPrefix = readPrefix();
        if (!exchange.getRequestMethod().equals("GET") || uri.getRawQuery() != null || !uri.getRawPath().startsWith(readPrefix)) {
            unexpectedRequests.add(exchange.getRequestMethod() + " " + uri);
            respond(exchange, new Answer(405, "{\"errors\":[\"1 error occurred:\\n\\t* unsupported operation\\n\\n\"]}"));
            return;
        }

        var headers = exchange.getRequestHeaders();
        var token = headers.getFirst("X-Vault-Token");
        tokens.add(token == null ? "" : token);
        namespaces.add(headerOrNone(headers.getFirst("X-Vault-Namespace")));
        vaultRequestHeaders.add(headerOrNone(headers.getFirst("X-Vault-Request")));
        var path = uri.getRawPath().substring(readPrefix.length());
        reads.add(path);

        // A hook that throws leaves the exchange to the server, which drops the connection.
        var hook = onRead;
        if (hook != null)
            hook.run(exchange);

        var given = answer;
        if (!TOKEN.equals(token))
            respond(exchange, new Answer(403, "{\"errors\":[\"permission denied\"]}"));
        else if (given != null)
            respond(exchange, given);
        else if (deleted.contains(path))
            respond(exchange, new Answer(404, envelope(Json.object("data", null, "metadata", metadata(true)), 0)));
        else if (!secrets.containsKey(path))
            respond(exchange, new Answer(404, "{\"errors\":[]}"));
        else
            respond(exchange, new Answer(200, kvVersion == VaultKvVersion.V2
                    ? envelope(Json.object("data", secrets.get(path), "metadata", metadata(false)), 0)
                    : envelope(secrets.get(path), 2764800)));
    }

    private static String headerOrNone(String value) {
        return value == null ? "(none)" : value;
    }

    private static Map<String, Object> metadata(boolean deleted) {
        return Json.object(
                "created_time", "2026-10-28T12:00:00.000000Z",
                "custom_metadata", null,
                "deletion_time", deleted ? "2026-10-28T13:00:00.000000Z" : "",
                "destroyed", false,
                "version", 3);
    }

    private static String envelope(Object data, int leaseDuration) {
        return Json.write(Json.object(
                "request_id", "0f3c2a8e-1b2d-4c5e-8f9a-0b1c2d3e4f5a",
                "lease_id", "",
                "renewable", false,
                "lease_duration", leaseDuration,
                "data", data,
                "wrap_info", null,
                "warnings", null,
                "auth", null,
                "mount_type", "kv"));
    }

    static void respond(HttpExchange exchange, Answer answer) throws IOException {
        var body = answer.body().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        answer.headers().forEach(exchange.getResponseHeaders()::set);
        exchange.sendResponseHeaders(answer.status(), body.length == 0 ? -1 : body.length);
        try (var out = exchange.getResponseBody()) {
            out.write(body);
        }
        exchange.close();
    }

    private static List<String> snapshot(List<String> list) {
        synchronized (list) {
            return List.copyOf(list);
        }
    }

    /** Just enough JSON writing for Vault's responses. */
    static final class Json {
        private Json() {
        }

        /** An ordered object from alternating names and values; values may be null. */
        static Map<String, Object> object(Object... namesAndValues) {
            var object = new LinkedHashMap<String, Object>();
            for (var i = 0; i < namesAndValues.length; i += 2)
                object.put((String) namesAndValues[i], namesAndValues[i + 1]);
            return object;
        }

        static String write(Object value) {
            var json = new StringBuilder();
            write(json, value);
            return json.toString();
        }

        private static void write(StringBuilder json, Object value) {
            switch (value) {
                case null -> json.append("null");
                case String s -> string(json, s);
                case Number n -> json.append(n);
                case Boolean b -> json.append(b);
                case Map<?, ?> map -> {
                    json.append('{');
                    var first = true;
                    for (var entry : map.entrySet()) {
                        if (!first)
                            json.append(',');
                        first = false;
                        string(json, (String) entry.getKey());
                        json.append(':');
                        write(json, entry.getValue());
                    }
                    json.append('}');
                }
                case List<?> list -> {
                    json.append('[');
                    for (var i = 0; i < list.size(); i++) {
                        if (i > 0)
                            json.append(',');
                        write(json, list.get(i));
                    }
                    json.append(']');
                }
                default -> throw new IllegalArgumentException("Can't write a " + value.getClass() + " as JSON.");
            }
        }

        private static void string(StringBuilder json, String s) {
            json.append('"');
            for (var i = 0; i < s.length(); i++) {
                var c = s.charAt(i);
                switch (c) {
                    case '"' -> json.append("\\\"");
                    case '\\' -> json.append("\\\\");
                    case '\n' -> json.append("\\n");
                    default -> {
                        if (c < 0x20)
                            json.append(String.format("\\u%04x", (int) c));
                        else
                            json.append(c);
                    }
                }
            }
            json.append('"');
        }
    }
}
