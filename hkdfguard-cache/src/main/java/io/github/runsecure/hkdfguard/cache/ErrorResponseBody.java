package io.github.runsecure.hkdfguard.cache;

import io.github.runsecure.hkdfguard.cache.JsonReader.Token;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Reads the error messages out of a secret store's JSON error response - one that holds nothing
 * secret, such as HashiCorp Vault's {"errors":["permission denied"]} - with the same strict reader
 * {@link SecretJsonBody} uses, since Java has no JSON parser of its own. Never use it on a body that
 * may hold a secret: it makes Strings.
 */
public final class ErrorResponseBody {
    /** The largest error body read; anything beyond it is ignored, and the body reads as not JSON. */
    public static final int MAX_BODY_LENGTH = 64 * 1024;

    private ErrorResponseBody() {
    }

    /**
     * Reads body to its end (or {@link #MAX_BODY_LENGTH} bytes) and returns the elements of its
     * top-level {@code arrayProperty}: a string as its text, anything else as its JSON text.
     *
     * @return the elements; empty if the body is a JSON object without that property; null if the
     *         body isn't a JSON object (a proxy's HTML page, say), or the property isn't an array
     * @throws IOException reading body failed
     */
    public static List<String> readStrings(InputStream body, String arrayProperty) throws IOException {
        Objects.requireNonNull(body, "body");
        Objects.requireNonNull(arrayProperty, "arrayProperty");

        var bytes = body.readNBytes(MAX_BODY_LENGTH);
        var reader = new JsonReader(bytes, bytes.length);
        try {
            if (!reader.read() || reader.token() != Token.START_OBJECT)
                return null;

            List<String> found = List.of();
            while (reader.read() && reader.token() == Token.PROPERTY_NAME) {
                var isArray = reader.valueTextEquals(arrayProperty);
                reader.read();
                if (!isArray) {
                    reader.skip();
                } else if (reader.token() != Token.START_ARRAY) {
                    return null;
                } else {
                    found = elements(reader, bytes);
                }
            }

            // Anything after the object makes it not JSON.
            return reader.read() ? null : found;
        } catch (JsonReader.Malformed e) {
            return null;
        }
    }

    private static List<String> elements(JsonReader reader, byte[] bytes) {
        var elements = new ArrayList<String>();
        while (reader.read() && reader.token() != Token.END_ARRAY) {
            var start = reader.tokenStart();
            if (reader.token() == Token.STRING) {
                elements.add(reader.getString());
                continue;
            }

            reader.skip();
            elements.add(new String(bytes, start, reader.bytesConsumed() - start, StandardCharsets.UTF_8));
        }
        return List.copyOf(elements);
    }
}
