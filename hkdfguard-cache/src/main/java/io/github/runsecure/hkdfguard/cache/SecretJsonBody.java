package io.github.runsecure.hkdfguard.cache;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.remote.JsonReader;
import io.github.runsecure.hkdfguard.remote.JsonReader.Token;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Takes a secret out of a JSON response body before an SDK can turn it into a String. The body is
 * read into an array of the library's own, the named string property is unescaped (and
 * base64-decoded, for a binary property) straight into another and handed to a
 * {@link SecretValueSink}, and what's returned is the same body with that value replaced by "" -
 * for the SDK to parse as usual, holding nothing secret. Every array that held the value is zeroed
 * before returning.
 * <p>
 * Unlike .NET, the JVM can't pin an array (see {@link ArrayUtility}): a compacting collector may
 * leave a moved copy behind, which zeroing can't reach.
 */
public final class SecretJsonBody {
    /** The largest body read: far beyond any secret store's response, so a larger one is refused. */
    public static final int MAX_BODY_LENGTH = 1024 * 1024;

    private static final int INITIAL_BUFFER_LENGTH = 16 * 1024;

    private SecretJsonBody() {
    }

    /**
     * Reads body to its end, hands the value of its top-level {@code textProperty} (as UTF-8 bytes,
     * with {@link SecretValueSink#setBytesWithJsonKeys}, so a JSON object's members are keys too) to
     * value, and returns the body with that value replaced by "". A missing, null or empty property
     * hands nothing over. body is read but not closed.
     *
     * @throws InvalidSecretDataException body isn't a JSON object, is {@link #MAX_BODY_LENGTH} bytes
     *                                    or more, or holds more than one non-empty secret value; or
     *                                    the value is a JSON object holding a member name more than
     *                                    once
     * @throws UncheckedIOException       reading body failed
     */
    public static byte[] capture(InputStream body, SecretValueSink value, String textProperty) {
        return capture(body, value, List.of(), textProperty, null);
    }

    /**
     * As {@link #capture(InputStream, SecretValueSink, String)}, or, when the body holds its
     * top-level {@code base64Property} instead, the bytes it encodes, whole. Both values are
     * replaced by "" in the body returned.
     *
     * @param base64Property null for none
     * @throws InvalidSecretDataException as for {@link #capture(InputStream, SecretValueSink, String)},
     *                                    or the base64 value isn't base64
     */
    public static byte[] capture(InputStream body, SecretValueSink value, String textProperty, String base64Property) {
        return capture(body, value, List.of(), textProperty, base64Property);
    }

    /**
     * As {@link #capture(InputStream, SecretValueSink, String, String)}, for a value nested in
     * objects: {@code textProperty} and {@code base64Property} are looked for in the object reached
     * through {@code objectPath}'s property names - ["data", "data"] for
     * {"data":{"data":{"value":"..."}}}. A path that leads to no object hands nothing over.
     *
     * @throws IllegalArgumentException   textProperty, or a name in objectPath, is null or empty
     * @throws InvalidSecretDataException as for
     *                                    {@link #capture(InputStream, SecretValueSink, String, String)}
     */
    public static byte[] capture(InputStream body, SecretValueSink value, List<String> objectPath, String textProperty, String base64Property) {
        if (textProperty == null || textProperty.isEmpty())
            throw new IllegalArgumentException("The text property is null or empty.");

        return read(body, value, objectPath, new Target(textProperty, base64Property, value));
    }

    /**
     * Reads body to its end and hands each member of the object reached through
     * {@code objectPath}'s property names to value as a key, as
     * {@link SecretValueSink#setBytesWithJsonKeys} describes - for a store whose secrets are sets of
     * keys, such as HashiCorp Vault's KV: ["data", "data"] for
     * {"data":{"data":{"username":"...","password":"..."}}}. A path that leads to no object hands
     * nothing over. body is read but not closed.
     *
     * @throws IllegalArgumentException   a name in objectPath is null or empty
     * @throws InvalidSecretDataException body isn't a JSON object, or is {@link #MAX_BODY_LENGTH}
     *                                    bytes or more; or the object holds a member name more than
     *                                    once
     * @throws UncheckedIOException       reading body failed
     */
    public static void captureKeys(InputStream body, SecretValueSink value, List<String> objectPath) {
        read(body, value, objectPath, new Target(null, null, value));
    }

    // Reads body and walks it for target; returns the body redacted, for a target with a text
    // property.
    private static byte[] read(InputStream body, SecretValueSink value, List<String> objectPath, Target target) {
        Objects.requireNonNull(body, "body");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(objectPath, "objectPath");
        for (var name : objectPath) {
            if (name == null || name.isEmpty())
                throw new IllegalArgumentException("A property name in the path is null or empty.");
        }

        var buffer = new byte[INITIAL_BUFFER_LENGTH];
        var length = 0;
        try {
            int read;
            while ((read = body.read(buffer, length, buffer.length - length)) > 0) {
                length += read;
                buffer = growIfFull(buffer, length);
            }

            return parse(buffer, length, objectPath, target);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } finally {
            ArrayUtility.zeroMemory(buffer);
        }
    }

    // buffer, or once it's full a copy twice its size, the original zeroed.
    private static byte[] growIfFull(byte[] buffer, int length) {
        if (length < buffer.length)
            return buffer;
        if (buffer.length >= MAX_BODY_LENGTH)
            throw new InvalidSecretDataException("The response body is " + MAX_BODY_LENGTH + " bytes or more.");

        var larger = Arrays.copyOf(buffer, Math.min(buffer.length * 2, MAX_BODY_LENGTH));
        ArrayUtility.zeroMemory(buffer);
        return larger;
    }

    private static byte[] parse(byte[] buffer, int length, List<String> objectPath, Target target) {
        var reader = new JsonReader(buffer, length);
        try {
            if (!reader.read() || reader.token() != Token.START_OBJECT)
                throw new InvalidSecretDataException("The response body isn't a JSON object.");

            readObject(reader, objectPath, target);
        } catch (JsonReader.Malformed e) {
            // Not chained, and never quoting the byte rejected, which may be in the secret.
            throw new InvalidSecretDataException("The response body isn't valid JSON (at byte " + e.position + " of line " + e.line + ").");
        }

        return target.textProperty == null ? new byte[0] : redact(buffer, length, target.secrets);
    }

    // What one read looks for - a text (and base64) property, or, with no text property, every
    // member as a key - and what it has found so far.
    private static final class Target {
        final String textProperty;
        final String base64Property;
        final SecretValueSink value;
        final List<int[]> secrets = new ArrayList<>(2);
        final Set<String> keys = new HashSet<>();
        boolean handedOver;

        Target(String textProperty, String base64Property, SecretValueSink value) {
            this.textProperty = textProperty;
            this.base64Property = base64Property;
            this.value = value;
        }
    }

    // Reads the properties of the object reader is at the start of, descending objectPath; returns
    // with reader at its end.
    private static void readObject(JsonReader reader, List<String> objectPath, Target target) {
        if (objectPath.isEmpty() && target.textProperty == null) {
            SecretJsonKeys.setKeys(reader, target.value, target.keys);
            return;
        }

        while (reader.read() && reader.token() == Token.PROPERTY_NAME) {
            if (!objectPath.isEmpty()) {
                var isParent = reader.valueTextEquals(objectPath.get(0));
                reader.read();
                if (isParent && reader.token() == Token.START_OBJECT)
                    readObject(reader, objectPath.subList(1, objectPath.size()), target);
                else
                    reader.skip();
                continue;
            }

            readProperty(reader, target);
        }
    }

    // Reads the property reader is at the name of, in the object holding the secret.
    private static void readProperty(JsonReader reader, Target target) {
        var isText = reader.valueTextEquals(target.textProperty);
        var isBase64 = !isText && target.base64Property != null && reader.valueTextEquals(target.base64Property);
        reader.read();

        if (!(isText || isBase64) || reader.token() != Token.STRING) {
            reader.skip();
            return;
        }

        if (reader.valueLength() > 0) {
            if (target.handedOver)
                throw new InvalidSecretDataException("The response body holds more than one secret value.");

            handOver(reader, isBase64, target.value);
            target.handedOver = true;
        }

        target.secrets.add(new int[] {reader.tokenStart(), reader.bytesConsumed()});
    }

    private static void handOver(JsonReader reader, boolean isBase64, SecretValueSink value) {
        // Unescaped, a string is never longer than it is escaped.
        var text = new byte[reader.valueLength()];
        byte[] encoded = null;
        byte[] bytes = null;
        try {
            var textLength = reader.copyString(text);
            if (!isBase64) {
                value.setBytesWithJsonKeys(SecretJsonKeys.exact(text, textLength));
                return;
            }

            encoded = SecretJsonKeys.exact(text, textLength);
            bytes = new byte[textLength / 4 * 3 + 3];
            int written;
            try {
                written = Base64.getDecoder().decode(encoded, bytes);
            } catch (IllegalArgumentException e) {
                // Not chained: the decoder's message quotes the character it rejected.
                throw new InvalidSecretDataException("The response body's binary secret value isn't base64.");
            }
            value.setBytes(SecretJsonKeys.exact(bytes, written));
        } finally {
            ArrayUtility.zeroMemory(text);
            ArrayUtility.zeroMemory(encoded);
            ArrayUtility.zeroMemory(bytes);
        }
    }

    // The body with each secret value's token - its quotes included - replaced by "".
    private static byte[] redact(byte[] json, int length, List<int[]> secrets) {
        var redactedLength = length;
        for (var secret : secrets)
            redactedLength -= secret[1] - secret[0] - 2;

        var redacted = new byte[redactedLength];
        var from = 0;
        var to = 0;
        for (var secret : secrets) {
            System.arraycopy(json, from, redacted, to, secret[0] - from);
            to += secret[0] - from;
            redacted[to++] = '"';
            redacted[to++] = '"';
            from = secret[1];
        }

        System.arraycopy(json, from, redacted, to, length - from);
        return redacted;
    }
}
