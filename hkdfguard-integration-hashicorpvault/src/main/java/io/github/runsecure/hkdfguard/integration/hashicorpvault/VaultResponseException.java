package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import io.github.runsecure.hkdfguard.remote.JsonReader;
import io.github.runsecure.hkdfguard.remote.JsonReader.Token;
import java.io.Serial;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Vault answered a {@link VaultClient} request with a status outside 200-399 (vault-client-go's
 * ResponseError). A request that gets no answer - Vault unreachable, say - fails with the
 * IOException java.net.http threw.
 */
public final class VaultResponseException extends VaultRequestException {
    @Serial
    private static final long serialVersionUID = 1L;

    // An array, not a List: a List isn't Serializable.
    private final String[] errors;
    private final byte[] rawResponseBytes;
    private final String requestMethod;
    private final URI requestUri;

    VaultResponseException(String message, int statusCode, List<String> errors, byte[] rawResponseBytes, String requestMethod, URI requestUri) {
        super(message, statusCode);
        this.errors = errors.toArray(String[]::new);
        this.rawResponseBytes = rawResponseBytes;
        this.requestMethod = requestMethod;
        this.requestUri = requestUri;
    }

    /** The errors Vault listed in its response; empty if it listed none. */
    public List<String> errors() {
        return List.of(errors);
    }

    /** A copy of the response body, when it held no errors to list; null otherwise. */
    public byte[] rawResponseBytes() {
        return rawResponseBytes == null ? null : rawResponseBytes.clone();
    }

    /** The method of the request Vault refused. */
    public String requestMethod() {
        return requestMethod;
    }

    /** The URI of the request Vault refused. */
    public URI requestUri() {
        return requestUri;
    }

    // The errors body[0, length) lists, as {"errors":[...]} or {"error":"..."}; failing those, the body itself.
    static VaultResponseException create(int status, byte[] body, int length, String method, URI uri) {
        var reason = VaultHttp.reasonPhrase(status);
        var errors = readErrors(body, length);
        if (errors != null && !errors.isEmpty())
            return new VaultResponseException(status + reason + ": " + String.join(", ", errors), status, errors, null, method, uri);

        var raw = length == 0 ? null : Arrays.copyOf(body, length);
        var message = raw == null ? status + reason : status + reason + ": " + new String(raw, StandardCharsets.UTF_8);
        return new VaultResponseException(message, status, List.of(), raw, method, uri);
    }

    private static List<String> readErrors(byte[] body, int length) {
        if (length == 0)
            return null;

        try {
            var reader = new JsonReader(body, length);
            if (!reader.read() || reader.token() != Token.START_OBJECT)
                return null;

            List<String> errors = null;
            String error = null;
            while (reader.read() && reader.token() == Token.PROPERTY_NAME) {
                if (reader.valueTextEquals("errors")) {
                    reader.read();
                    errors = readStrings(reader);
                } else if (reader.valueTextEquals("error")) {
                    reader.read();
                    if (reader.token() == Token.STRING)
                        error = reader.getString();
                    else
                        reader.skip();
                } else {
                    reader.read();
                    reader.skip();
                }
            }

            // Anything after the object makes it not JSON: the reader is given the whole body.
            if (reader.read())
                return null;
            if (errors != null && !errors.isEmpty())
                return errors;
            return error == null || error.isEmpty() ? null : List.of(error);
        } catch (JsonReader.Malformed e) {
            return null;
        }
    }

    // A JSON array of strings; null if it is anything else.
    private static List<String> readStrings(JsonReader reader) {
        if (reader.token() != Token.START_ARRAY) {
            reader.skip();
            return null;
        }

        var strings = new ArrayList<String>();
        var allStrings = true;
        while (reader.read() && reader.token() != Token.END_ARRAY) {
            if (reader.token() == Token.STRING) {
                strings.add(reader.getString());
            } else {
                allStrings = false;
                reader.skip();
            }
        }
        return allStrings ? strings : null;
    }
}
