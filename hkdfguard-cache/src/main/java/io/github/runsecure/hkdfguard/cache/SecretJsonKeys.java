package io.github.runsecure.hkdfguard.cache;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.cache.JsonReader.Token;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

// Hands a JSON object's members to a SecretValueSink as keys, never as strings: each value is
// unescaped (or, for a number, true or false, copied) into an array of its own, handed over, and
// zeroed.
final class SecretJsonKeys {
    private SecretJsonKeys() {
    }

    /**
     * When json is exactly one JSON object, hands each of its members over as a key; anything else
     * - plain text that merely starts like JSON included - hands nothing over. The whole value is
     * checked first, so malformed JSON never hands over part of its members.
     */
    static void trySetKeys(byte[] json, SecretValueSink value) {
        if (!isObject(json))
            return;

        var reader = new JsonReader(json, json.length);
        reader.read();
        setKeys(reader, value, new HashSet<>());
    }

    /**
     * Hands each member of the object reader is at the start of over as a key, leaving reader at
     * its end. A string is handed over as its UTF-8 bytes; a number, true or false as its JSON text;
     * null, an object, an array, an empty string, or a member whose name isn't a key a name can
     * hold, isn't handed over. {@code seen} collects the member names, across every object handed
     * over for one secret.
     *
     * @throws InvalidSecretDataException a member name is in seen already
     */
    static void setKeys(JsonReader reader, SecretValueSink value, Set<String> seen) {
        while (reader.read() && reader.token() == Token.PROPERTY_NAME) {
            var key = reader.getString();
            // Not named: a key is part of a lookup name, logged only with sensitive logging on.
            if (!seen.add(key))
                throw new InvalidSecretDataException("The secret holds a key more than once.");

            reader.read();
            var token = reader.token();
            if (RemoteSecretCache.isValidKey(key)
                    && (token == Token.STRING || token == Token.NUMBER || token == Token.TRUE || token == Token.FALSE))
                setKey(reader, key, value);
            else
                reader.skip();
        }
    }

    private static void setKey(JsonReader reader, String key, SecretValueSink value) {
        // Unescaped, a string is never longer than it is escaped; anything else is copied as it is.
        var buffer = new byte[reader.valueLength()];
        try {
            var length = reader.token() == Token.STRING ? reader.copyString(buffer) : reader.copyRaw(buffer);
            value.setKeyBytes(key, exact(buffer, length));
        } finally {
            ArrayUtility.zeroMemory(buffer);
        }
    }

    /** buffer, or a copy of its first length bytes when it is longer - for the caller to zero. */
    static byte[] exact(byte[] buffer, int length) {
        return length == buffer.length ? buffer : Arrays.copyOf(buffer, length);
    }

    // One JSON object and nothing after it but whitespace.
    private static boolean isObject(byte[] json) {
        var reader = new JsonReader(json, json.length);
        try {
            if (!reader.read() || reader.token() != Token.START_OBJECT)
                return false;

            reader.skip();
            return !reader.read();
        } catch (JsonReader.Malformed e) {
            return false;
        }
    }
}
