package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import io.github.runsecure.hkdfguard.remote.JsonReader;
import io.github.runsecure.hkdfguard.remote.JsonReader.Token;
import java.nio.CharBuffer;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

/**
 * Reads Vault's response body into a {@link VaultResponse}: the standard envelope when it has a
 * "data" member (as vault-client-go decides) - or "auth" or "wrap_info", so a token is never
 * mistaken for data - otherwise the body whole as its data (sys/health, sys/leader...). The tokens
 * in auth.client_token and wrap_info.token are protected straight from the response's bytes, so
 * neither ever becomes a String; members of data named in omittedData - a token lookup's id, which
 * is the token itself - are skipped unread.
 */
final class VaultResponseReader {
    private VaultResponseReader() {
    }

    /**
     * body[0, length) as a response, data read with reader; null if it is empty.
     *
     * @throws VaultJsonException the body isn't JSON, or not of the shape reader reads
     */
    static <T> VaultResponse<T> read(byte[] body, int length, DataProtector tokenProtector, Function<JsonValue, T> reader) {
        return read(body, length, tokenProtector, reader, java.util.Set.of());
    }

    /** As {@link #read(byte[], int, DataProtector, Function)}, skipping data's members named in omittedData. */
    static <T> VaultResponse<T> read(byte[] body, int length, DataProtector tokenProtector, Function<JsonValue, T> reader,
            java.util.Set<String> omittedData) {
        if (length == 0)
            return null;
        if (!isEnvelope(body, length))
            return new VaultResponse<>(null, null, 0, false, JsonValue.parse(body, length).readModel(reader), null, null, null);

        try {
            var json = new JsonReader(body, length);
            json.read();
            String requestId = null;
            String leaseId = null;
            long leaseDuration = 0;
            var renewable = false;
            T data = null;
            List<String> warnings = null;
            VaultResponseAuth auth = null;
            VaultResponseWrapInfo wrapInfo = null;
            while (json.read() && json.token() == Token.PROPERTY_NAME) {
                var name = json.getString();
                json.read();
                switch (name) {
                    case "auth" -> auth = readAuth(json, tokenProtector);
                    case "wrap_info" -> wrapInfo = readWrapInfo(json, tokenProtector);
                    default -> {
                        var value = name.equals("data") ? JsonValue.read(json, omittedData) : JsonValue.read(json);
                        switch (name) {
                            case "request_id" -> requestId = value.readString();
                            case "lease_id" -> leaseId = value.readString();
                            case "lease_duration" -> leaseDuration = orZero(value.readLong());
                            case "renewable" -> renewable = Boolean.TRUE.equals(value.readBoolean());
                            case "data" -> data = value.readModel(reader);
                            case "warnings" -> warnings = value.readList(JsonValue::readString);
                            default -> {
                                // Not part of the envelope.
                            }
                        }
                    }
                }
            }
            if (json.read())
                throw new VaultJsonException("Vault's response holds more than one JSON value.");

            return new VaultResponse<>(requestId, leaseId, leaseDuration, renewable, data, warnings, auth, wrapInfo);
        } catch (JsonReader.Malformed e) {
            throw new VaultJsonException("Vault's response isn't JSON: " + e.getMessage());
        }
    }

    // Whether body is an object with a "data", "auth" or "wrap_info" member. Malformed, it isn't.
    private static boolean isEnvelope(byte[] body, int length) {
        try {
            var reader = new JsonReader(body, length);
            if (!reader.read() || reader.token() != Token.START_OBJECT)
                return false;

            while (reader.read() && reader.token() == Token.PROPERTY_NAME) {
                if (reader.valueTextEquals("data") || reader.valueTextEquals("auth") || reader.valueTextEquals("wrap_info"))
                    return true;
                reader.read();
                reader.skip();
            }
            return false;
        } catch (JsonReader.Malformed e) {
            return false;
        }
    }

    private static VaultResponseAuth readAuth(JsonReader json, DataProtector tokenProtector) {
        if (json.token() == Token.NULL)
            return null;
        if (json.token() != Token.START_OBJECT)
            throw new VaultJsonException("Expected a JSON object for auth.");

        var members = readMembers(json, "client_token", tokenProtector);
        var m = members.values;
        return new VaultResponseAuth(members.token,
                m.getOrDefault("accessor", JsonValue.NULL).readString(),
                m.getOrDefault("policies", JsonValue.NULL).readList(JsonValue::readString),
                m.getOrDefault("token_policies", JsonValue.NULL).readList(JsonValue::readString),
                m.getOrDefault("identity_policies", JsonValue.NULL).readList(JsonValue::readString),
                m.getOrDefault("metadata", JsonValue.NULL).readMap(JsonValue::readString),
                Boolean.TRUE.equals(m.getOrDefault("orphan", JsonValue.NULL).readBoolean()),
                m.getOrDefault("entity_id", JsonValue.NULL).readString(),
                orZero(m.getOrDefault("lease_duration", JsonValue.NULL).readLong()),
                Boolean.TRUE.equals(m.getOrDefault("renewable", JsonValue.NULL).readBoolean()),
                m.getOrDefault("mfa_requirement", JsonValue.NULL).readModel(VaultMfaRequirement::fromJson));
    }

    private static VaultResponseWrapInfo readWrapInfo(JsonReader json, DataProtector tokenProtector) {
        if (json.token() == Token.NULL)
            return null;
        if (json.token() != Token.START_OBJECT)
            throw new VaultJsonException("Expected a JSON object for wrap_info.");

        var members = readMembers(json, "token", tokenProtector);
        var m = members.values;
        return new VaultResponseWrapInfo(members.token,
                m.getOrDefault("accessor", JsonValue.NULL).readString(),
                orZero(m.getOrDefault("ttl", JsonValue.NULL).readLong()),
                m.getOrDefault("creation_time", JsonValue.NULL).readDateTime(),
                m.getOrDefault("creation_path", JsonValue.NULL).readString(),
                m.getOrDefault("wrapped_accessor", JsonValue.NULL).readString());
    }

    private record Members(StaticVaultToken token, Map<String, JsonValue> values) {
    }

    // The members of the object json has just started, the one named tokenName protected rather than read.
    private static Members readMembers(JsonReader json, String tokenName, DataProtector tokenProtector) {
        StaticVaultToken token = null;
        var values = new HashMap<String, JsonValue>();
        while (json.read() && json.token() == Token.PROPERTY_NAME) {
            var isToken = json.valueTextEquals(tokenName);
            var name = json.getString();
            json.read();
            if (isToken)
                token = protectToken(json, tokenProtector);
            else
                values.put(name, JsonValue.read(json));
        }
        return new Members(token, values);
    }

    // The token string json has just read, protected: unescaped into arrays that are zeroed once
    // it's encrypted from them. Null for null or an empty string.
    private static StaticVaultToken protectToken(JsonReader json, DataProtector tokenProtector) {
        if (json.token() == Token.NULL)
            return null;
        if (json.token() != Token.STRING) {
            json.skip();
            throw new VaultJsonException("Expected a token string.");
        }

        // Unescaped, a string is never longer than it is escaped.
        var bytes = new byte[json.valueLength()];
        char[] chars = null;
        try {
            var length = json.copyString(bytes);
            if (length == 0)
                return null;

            chars = new char[length];
            for (var i = 0; i < length; i++) {
                // A token is ASCII: anything else isn't one, whatever it decodes to.
                if (bytes[i] < 0)
                    throw new VaultJsonException("Vault returned a token that isn't one: printable ASCII, with no spaces.");
                chars[i] = (char) bytes[i];
            }
            if (!VaultHttp.isValidToken(CharBuffer.wrap(chars)))
                throw new VaultJsonException("Vault returned a token that isn't one: printable ASCII, with no spaces.");

            return new StaticVaultToken(tokenProtector.encrypt(CharBuffer.wrap(chars)));
        } finally {
            ArrayUtility.zeroMemory(bytes);
            ArrayUtility.zeroMemory(chars);
        }
    }

    private static long orZero(Long value) {
        return value == null ? 0 : value;
    }
}
