package io.github.runsecure.hkdfguard.keywrapping.hashicorpvault;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.runsecure.hkdfguard.remote.JsonReader;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A transit secrets engine behind Vault's HTTP API, served over plain http on 127.0.0.1 (which the
 * wrapper allows on loopback). A POST to encrypt, decrypt or datakey/wrapped for a key it holds,
 * with the expected token, is answered as Vault 1.19 answers it: the ciphertext is
 * "vault:v{version}:" and base64 of AES-GCM under that key version's own local key, with
 * associated_data as the AAD, so decrypt fails unless the key, its version and the context all
 * match. A key can be rotated, and given a min_decryption_version. datakey/wrapped ignores
 * associated_data and says so in its warnings, as Vault does. A request without the token is
 * refused with 403. Any other request is recorded in {@link #unexpectedRequests} and refused.
 */
final class FakeTransit implements AutoCloseable {
    static final String TOKEN = "hvs.CAESIFakeTokenForTests";

    static final String KEY_NAME = "myapp-kek";

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final Pattern CIPHERTEXT = Pattern.compile("vault:v(\\d+):(.*)", Pattern.DOTALL);

    /** An answer given as it is: a status, a body ("" for none) and any extra headers. */
    record Answer(int status, String body, Map<String, String> headers) {
        Answer(int status, String body) {
            this(status, body, Map.of());
        }
    }

    /** One transit request as it arrived: the body is a copy. */
    record TransitRequest(String operation, String key, byte[] body, String token, String namespace, String vaultRequest,
            String contentType) {
        String bodyText() {
            return new String(body, StandardCharsets.UTF_8);
        }

        /** The body's fields: a string as its text, anything else as its JSON text. */
        Map<String, String> json() {
            return parseFlat(body);
        }

        String field(String name) {
            return json().get(name);
        }
    }

    /** Answers a request in place of the engine; null to let the engine answer. */
    @FunctionalInterface
    interface Answerer {
        Answer answer(TransitRequest request, int count);
    }

    /** Runs inside a request before it answers: may hold it open, answer it itself, or throw to drop the connection. */
    @FunctionalInterface
    interface RequestHook {
        void run(HttpExchange exchange) throws IOException;
    }

    private final HttpServer server;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    private final String mountPath;
    private final String pathPrefix;
    // Each key's versions' AES keys, version 1 first.
    private final Map<String, List<byte[]>> keys = new ConcurrentHashMap<>();
    private final Map<String, Integer> minDecryptionVersions = new ConcurrentHashMap<>();
    private final List<TransitRequest> requests = new CopyOnWriteArrayList<>();
    private final List<String> unexpectedRequests = Collections.synchronizedList(new ArrayList<>());

    /** When set, answers a request with the right token in place of the engine. */
    volatile Answerer answer;

    /** When set, runs inside every transit request before it answers. */
    volatile RequestHook onRequest;

    /** Answers as a Vault too old for associated_data would: ignoring it, with a warning. */
    volatile boolean ignoresAssociatedData;

    FakeTransit() {
        this("transit", "");
    }

    /**
     * @param mountPath  where the engine is mounted, as the wrapper's options say
     * @param pathPrefix the path /v1/ is under, for an address with a path prefix: "" or "/vault"
     */
    FakeTransit(String mountPath, String pathPrefix) {
        this.mountPath = mountPath;
        this.pathPrefix = pathPrefix;
        addKey(KEY_NAME);
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

    /** The address of a transit path, e.g. "encrypt/other-kek", for a redirect to point at. */
    URI transitUri(String path) {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort() + pathPrefix + "/v1/" + mountPath + "/" + path);
    }

    void addKey(String name) {
        var versions = new CopyOnWriteArrayList<byte[]>();
        versions.add(randomBytes(32));
        keys.put(name, versions);
    }

    /** Adds a version to the key, as transit/keys/{name}/rotate does; new ciphertexts use it. */
    void rotate(String name) {
        keys.get(name).add(randomBytes(32));
    }

    /** Refuses ciphertexts made under an earlier version, as Vault's min_decryption_version does. */
    void setMinDecryptionVersion(String name, int version) {
        minDecryptionVersions.put(name, version);
    }

    /** Every transit request, in order. */
    List<TransitRequest> requests() {
        return List.copyOf(requests);
    }

    /** Every other request, as "METHOD path?query". */
    List<String> unexpectedRequests() {
        synchronized (unexpectedRequests) {
            return List.copyOf(unexpectedRequests);
        }
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }

    private void handle(HttpExchange exchange) throws IOException {
        var uri = exchange.getRequestURI();
        var prefix = pathPrefix + "/v1/" + mountPath + "/";
        var route = uri.getRawPath().startsWith(prefix) ? uri.getRawPath().substring(prefix.length()) : "";
        String operation;
        String key;
        if (route.startsWith("encrypt/")) {
            operation = "encrypt";
            key = route.substring("encrypt/".length());
        } else if (route.startsWith("decrypt/")) {
            operation = "decrypt";
            key = route.substring("decrypt/".length());
        } else if (route.startsWith("datakey/wrapped/")) {
            operation = "datakey";
            key = route.substring("datakey/wrapped/".length());
        } else {
            operation = "";
            key = "";
        }
        if (!exchange.getRequestMethod().equals("POST") || operation.isEmpty() || key.isEmpty() || key.contains("/") || uri.getRawQuery() != null) {
            unexpectedRequests.add(exchange.getRequestMethod() + " " + uri);
            respond(exchange, new Answer(405, "{\"errors\":[\"1 error occurred:\\n\\t* unsupported operation\\n\\n\"]}"));
            return;
        }

        var headers = exchange.getRequestHeaders();
        var token = headers.getFirst("X-Vault-Token");
        var body = exchange.getRequestBody().readAllBytes();
        var recorded = new TransitRequest(operation, key, body, token == null ? "" : token, headers.getFirst("X-Vault-Namespace"),
                headers.getFirst("X-Vault-Request"), headers.getFirst("Content-Type"));
        requests.add(recorded);

        // A hook that throws leaves the exchange to the server, which drops the connection.
        var hook = onRequest;
        if (hook != null)
            hook.run(exchange);

        if (!TOKEN.equals(token)) {
            respond(exchange, new Answer(403, "{\"errors\":[\"1 error occurred:\\n\\t* permission denied\\n\\n\"]}"));
            return;
        }
        var answerer = answer;
        var given = answerer != null ? answerer.answer(recorded, requests.size()) : null;
        if (given != null) {
            respond(exchange, given);
            return;
        }
        var versions = keys.get(key);
        if (versions == null) {
            respond(exchange, new Answer(400, "{\"errors\":[\"encryption key not found\"]}"));
            return;
        }

        respond(exchange, engine(operation, key, versions, recorded.json()));
    }

    private Answer engine(String operation, String key, List<byte[]> versions, Map<String, String> json) {
        var ignored = new ArrayList<String>();
        for (var name : json.keySet()) {
            var known = switch (operation) {
                case "encrypt" -> name.equals("plaintext") || (name.equals("associated_data") && !ignoresAssociatedData);
                case "decrypt" -> name.equals("ciphertext") || (name.equals("associated_data") && !ignoresAssociatedData);
                default -> name.equals("bits");
            };
            if (!known)
                ignored.add(name);
        }

        var aad = ignored.contains("associated_data") || json.get("associated_data") == null
                ? new byte[0]
                : Base64.getDecoder().decode(json.get("associated_data"));
        var warnings = ignored.isEmpty() ? null : List.<Object>of("Endpoint ignored these unrecognized parameters: [" + String.join(" ", ignored) + "]");
        var latest = versions.size();

        switch (operation) {
            case "encrypt" -> {
                var plaintext = Base64.getDecoder().decode(json.get("plaintext"));
                return new Answer(200, envelope(Json.object("ciphertext", seal(versions.get(latest - 1), latest, plaintext, aad), "key_version", latest),
                        warnings));
            }
            case "datakey" -> {
                var bits = Integer.parseInt(json.get("bits"));
                return new Answer(200, envelope(Json.object("ciphertext", seal(versions.get(latest - 1), latest, randomBytes(bits / 8), aad),
                        "key_version", latest), warnings));
            }
            default -> {
                var matcher = CIPHERTEXT.matcher(json.get("ciphertext"));
                if (!matcher.matches())
                    return new Answer(400, "{\"errors\":[\"invalid ciphertext: no prefix\"]}");
                var version = Integer.parseInt(matcher.group(1));
                if (version < minDecryptionVersions.getOrDefault(key, 1))
                    return new Answer(400, "{\"errors\":[\"ciphertext or signature version is disallowed by policy (too old)\"]}");
                if (version < 1 || version > latest)
                    return new Answer(400, "{\"errors\":[\"invalid key version\"]}");

                byte[] sealed;
                try {
                    sealed = Base64.getDecoder().decode(matcher.group(2));
                } catch (IllegalArgumentException e) {
                    return new Answer(400, "{\"errors\":[\"invalid ciphertext: could not decode\"]}");
                }
                var plaintext = open(versions.get(version - 1), sealed, aad);
                return plaintext == null
                        ? new Answer(400, "{\"errors\":[\"cipher: message authentication failed\"]}")
                        : new Answer(200, envelope(Json.object("plaintext", Base64.getEncoder().encodeToString(plaintext)), warnings));
            }
        }
    }

    /** A body shaped as Vault shapes a successful answer. */
    static String envelope(Object data, List<Object> warnings) {
        return Json.write(Json.object(
                "request_id", "0f3c2a8e-1b2d-4c5e-8f9a-0b1c2d3e4f5a",
                "lease_id", "",
                "renewable", false,
                "lease_duration", 0,
                "data", data,
                "wrap_info", null,
                "warnings", warnings,
                "auth", null,
                "mount_type", "transit"));
    }

    static String envelope(Object data) {
        return envelope(data, null);
    }

    static byte[] randomBytes(int length) {
        var bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static String seal(byte[] key, int version, byte[] plaintext, byte[] aad) {
        try {
            var nonce = randomBytes(12);
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
            cipher.updateAAD(aad);
            var sealed = cipher.doFinal(plaintext);
            var blob = new byte[12 + sealed.length];
            System.arraycopy(nonce, 0, blob, 0, 12);
            System.arraycopy(sealed, 0, blob, 12, sealed.length);
            return "vault:v" + version + ":" + Base64.getEncoder().encodeToString(blob);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] open(byte[] key, byte[] blob, byte[] aad) {
        if (blob.length < 28)
            return null;
        try {
            var cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, blob, 0, 12));
            cipher.updateAAD(aad);
            return cipher.doFinal(blob, 12, blob.length - 12);
        } catch (GeneralSecurityException e) {
            return null;
        }
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

    // A flat JSON object's fields - a string as its text, a number or literal as its JSON text - read
    // with the wrapper's own reader.
    private static Map<String, String> parseFlat(byte[] body) {
        var reader = new JsonReader(body, body.length);
        var fields = new LinkedHashMap<String, String>();
        if (!reader.read() || reader.token() != JsonReader.Token.START_OBJECT)
            throw new IllegalArgumentException("Not a JSON object: " + new String(body, StandardCharsets.UTF_8));
        while (reader.read() && reader.token() == JsonReader.Token.PROPERTY_NAME) {
            var name = reader.getString();
            reader.read();
            switch (reader.token()) {
                case STRING -> fields.put(name, reader.getString());
                case START_OBJECT, START_ARRAY -> throw new IllegalArgumentException("Not a flat object.");
                default -> {
                    var raw = new byte[reader.valueLength()];
                    fields.put(name, new String(raw, 0, reader.copyRaw(raw), StandardCharsets.UTF_8));
                }
            }
        }
        if (reader.read())
            throw new IllegalArgumentException("Something after the object.");
        return fields;
    }

    /** Just enough JSON writing for Vault's responses: escapes as Vault's (Go's) encoder does, leaving '+' alone. */
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
                    case '\t' -> json.append("\\t");
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
