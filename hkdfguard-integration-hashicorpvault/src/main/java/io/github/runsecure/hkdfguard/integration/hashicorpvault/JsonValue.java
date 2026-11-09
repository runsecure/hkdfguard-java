package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import io.github.runsecure.hkdfguard.remote.JsonReader;
import io.github.runsecure.hkdfguard.remote.JsonReader.Token;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

/**
 * A JSON value from a Vault response: what the client returns where Vault's spec types a value
 * loosely (a secret's data, free-form metadata), and what the generated models are read from.
 * Immutable; objects keep their members in document order, the last of a repeated name winning.
 * <p>
 * The {@code as...} methods are strict: each throws {@link VaultJsonException} for a value of
 * another kind. The {@code read...} methods are what the generated models read members with, as
 * leniently as the .NET client: each returns null for JSON null, and accepts what Vault writes in
 * place of what its spec declares - a number or boolean where a string is declared (its text), an
 * object or array there (its JSON text), a number in a string where a number is declared.
 * <p>
 * Strings are ordinary Strings, as in any API client. To read a secret into memory an application
 * uses, prefer the HashiCorp Vault secret cache, which never makes one a String.
 */
public final class JsonValue {
    /** What kind of JSON value it is. */
    public enum Kind {
        NULL, STRING, NUMBER, BOOLEAN, OBJECT, ARRAY
    }

    /** JSON null; also what {@link #member} returns for a member that isn't there. */
    public static final JsonValue NULL = new JsonValue(Kind.NULL, null, false, null, null);

    private static final JsonValue TRUE = new JsonValue(Kind.BOOLEAN, null, true, null, null);
    private static final JsonValue FALSE = new JsonValue(Kind.BOOLEAN, null, false, null, null);

    private final Kind kind;
    // A string's value, or a number's JSON text.
    private final String text;
    private final boolean bool;
    private final Map<String, JsonValue> members;
    private final List<JsonValue> elements;

    private JsonValue(Kind kind, String text, boolean bool, Map<String, JsonValue> members, List<JsonValue> elements) {
        this.kind = kind;
        this.text = text;
        this.bool = bool;
        this.members = members;
        this.elements = elements;
    }

    /** A string. */
    public static JsonValue of(String value) {
        return new JsonValue(Kind.STRING, Objects.requireNonNull(value, "value"), false, null, null);
    }

    /**
     * json, which must be one JSON value (RFC 8259) and nothing else.
     *
     * @throws VaultJsonException json isn't JSON
     */
    public static JsonValue parse(String json) {
        var bytes = json.getBytes(StandardCharsets.UTF_8);
        return parse(bytes, bytes.length);
    }

    /** json[0, length) as one JSON value. */
    static JsonValue parse(byte[] json, int length) {
        try {
            var reader = new JsonReader(json, length);
            if (!reader.read())
                throw new VaultJsonException("Expected JSON, found nothing.");
            var value = read(reader);
            if (reader.read())
                throw new VaultJsonException("Expected one JSON value; more follows it.");
            return value;
        } catch (JsonReader.Malformed e) {
            throw new VaultJsonException(e.getMessage());
        }
    }

    /**
     * As {@link #read(JsonReader)}, but an object's members named in omitted - at its top level
     * only - are skipped without being read, so a string among them never becomes a String.
     */
    static JsonValue read(JsonReader reader, java.util.Set<String> omitted) {
        if (omitted.isEmpty() || reader.token() != Token.START_OBJECT)
            return read(reader);

        var members = new LinkedHashMap<String, JsonValue>();
        while (reader.read() && reader.token() == Token.PROPERTY_NAME) {
            var name = reader.getString();
            reader.read();
            if (omitted.contains(name))
                reader.skip();
            else
                members.put(name, read(reader));
        }
        return new JsonValue(Kind.OBJECT, null, false, Collections.unmodifiableMap(members), null);
    }

    /** The value reader has just read the first token of, leaving the reader at its last token. */
    static JsonValue read(JsonReader reader) {
        return switch (reader.token()) {
            case NULL -> NULL;
            case TRUE -> TRUE;
            case FALSE -> FALSE;
            case STRING -> new JsonValue(Kind.STRING, reader.getString(), false, null, null);
            case NUMBER -> {
                var raw = new byte[reader.valueLength()];
                reader.copyRaw(raw);
                yield new JsonValue(Kind.NUMBER, new String(raw, StandardCharsets.US_ASCII), false, null, null);
            }
            case START_OBJECT -> {
                var members = new LinkedHashMap<String, JsonValue>();
                while (reader.read() && reader.token() == Token.PROPERTY_NAME) {
                    var name = reader.getString();
                    reader.read();
                    members.put(name, read(reader));
                }
                yield new JsonValue(Kind.OBJECT, null, false, Collections.unmodifiableMap(members), null);
            }
            case START_ARRAY -> {
                var elements = new ArrayList<JsonValue>();
                while (reader.read() && reader.token() != Token.END_ARRAY)
                    elements.add(read(reader));
                yield new JsonValue(Kind.ARRAY, null, false, null, Collections.unmodifiableList(elements));
            }
            default -> throw new VaultJsonException("Expected a JSON value, not " + reader.token() + ".");
        };
    }

    public Kind kind() {
        return kind;
    }

    public boolean isNull() {
        return kind == Kind.NULL;
    }

    /** The member named name of an object; {@link #NULL} if it has none, or this isn't an object. */
    public JsonValue member(String name) {
        if (kind != Kind.OBJECT)
            return NULL;
        var value = members.get(name);
        return value == null ? NULL : value;
    }

    /**
     * This value, which must be an object.
     *
     * @param what what it is read as, for the message, e.g. "KvV2ReadResponse"
     * @throws VaultJsonException it isn't an object
     */
    public JsonValue requireObject(String what) {
        if (kind != Kind.OBJECT)
            throw new VaultJsonException("Expected a JSON object for " + what + ", not " + describe() + ".");
        return this;
    }

    // --- Strict ------------------------------------------------------------------------------

    /** A string's value. */
    public String asString() {
        expect(Kind.STRING);
        return text;
    }

    /** A number's value, which must be an integer that fits a long. */
    public long asLong() {
        expect(Kind.NUMBER);
        return parseLong(text);
    }

    /** A number's value. */
    public double asDouble() {
        expect(Kind.NUMBER);
        return Double.parseDouble(text);
    }

    /** A number's value, exactly. */
    public BigDecimal asBigDecimal() {
        expect(Kind.NUMBER);
        return new BigDecimal(text);
    }

    /** A boolean's value. */
    public boolean asBoolean() {
        expect(Kind.BOOLEAN);
        return bool;
    }

    /** An object's members, in document order; unmodifiable. */
    public Map<String, JsonValue> asMap() {
        expect(Kind.OBJECT);
        return members;
    }

    /** An array's elements; unmodifiable. */
    public List<JsonValue> asList() {
        expect(Kind.ARRAY);
        return elements;
    }

    // --- Lenient, for the generated models ------------------------------------------------------

    /** A string as it is; a number or boolean as its text; an object or array as its JSON text; null for null. */
    public String readString() {
        return switch (kind) {
            case NULL -> null;
            case STRING, NUMBER -> text;
            case BOOLEAN -> bool ? "true" : "false";
            default -> toString();
        };
    }

    /** A number, or a string holding one, that fits an int; null for null. */
    public Integer readInteger() {
        var value = readLong();
        if (value == null)
            return null;
        if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE)
            throw new VaultJsonException("Expected a 32-bit integer; the number doesn't fit.");
        return value.intValue();
    }

    /** A number, or a string holding one, that fits a long; null for null. */
    public Long readLong() {
        return switch (kind) {
            case NULL -> null;
            case NUMBER, STRING -> parseLong(text);
            default -> throw mismatch("an integer");
        };
    }

    /** A number, or a string holding one; null for null. */
    public Double readDouble() {
        return switch (kind) {
            case NULL -> null;
            case NUMBER -> Double.parseDouble(text);
            case STRING -> {
                try {
                    yield Double.parseDouble(text.strip());
                } catch (NumberFormatException e) {
                    throw new VaultJsonException("Expected a number; the string doesn't hold one.");
                }
            }
            default -> throw mismatch("a number");
        };
    }

    /** A boolean; null for null. */
    public Boolean readBoolean() {
        return switch (kind) {
            case NULL -> null;
            case BOOLEAN -> bool;
            default -> throw mismatch("a boolean");
        };
    }

    /**
     * An RFC 3339 date-time as Vault (Go) writes it, up to nine fractional digits, assumed UTC
     * without an offset; null for null or an empty string.
     */
    public OffsetDateTime readDateTime() {
        if (kind == Kind.NULL)
            return null;
        if (kind != Kind.STRING)
            throw mismatch("a date-time string");
        if (text.isEmpty())
            return null;

        try {
            return OffsetDateTime.parse(text, DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        } catch (DateTimeParseException e) {
            try {
                return LocalDateTime.parse(text, DateTimeFormatter.ISO_LOCAL_DATE_TIME).atOffset(ZoneOffset.UTC);
            } catch (DateTimeParseException ignored) {
                throw new VaultJsonException("Expected a date-time; the string isn't one.");
            }
        }
    }

    /** An array, each element read with element; null for null. Unmodifiable. */
    public <T> List<T> readList(Function<JsonValue, ? extends T> element) {
        if (kind == Kind.NULL)
            return null;
        if (kind != Kind.ARRAY)
            throw mismatch("an array");

        var list = new ArrayList<T>(elements.size());
        for (var e : elements)
            list.add(element.apply(e));
        return Collections.unmodifiableList(list);
    }

    /** An object, each member's value read with value; null for null. Unmodifiable, in document order. */
    public <T> Map<String, T> readMap(Function<JsonValue, ? extends T> value) {
        if (kind == Kind.NULL)
            return null;
        if (kind != Kind.OBJECT)
            throw mismatch("an object");

        var map = new LinkedHashMap<String, T>();
        for (var member : members.entrySet())
            map.put(member.getKey(), value.apply(member.getValue()));
        return Collections.unmodifiableMap(map);
    }

    /** An object as its members' JSON values; null for null. */
    public Map<String, JsonValue> readJsonMap() {
        if (kind == Kind.NULL)
            return null;
        if (kind != Kind.OBJECT)
            throw mismatch("an object");
        return members;
    }

    /** This value read with reader - a model's fromJson; null for null. */
    public <T> T readModel(Function<JsonValue, ? extends T> reader) {
        return kind == Kind.NULL ? null : reader.apply(this);
    }

    /** This value; null for null. */
    public JsonValue readJson() {
        return kind == Kind.NULL ? null : this;
    }

    /**
     * This value as plain Java: a Map of String to Object (in document order), a List, a String, a
     * Long (an integer that fits one) or BigDecimal (any other number), a Boolean, or null.
     */
    public Object readObject() {
        return switch (kind) {
            case NULL -> null;
            case STRING -> text;
            case BOOLEAN -> bool;
            case NUMBER -> {
                var decimal = new BigDecimal(text);
                try {
                    yield decimal.longValueExact();
                } catch (ArithmeticException e) {
                    yield decimal;
                }
            }
            case OBJECT -> readMap(JsonValue::readObject);
            case ARRAY -> readList(JsonValue::readObject);
        };
    }

    /** This value as compact JSON text. */
    @Override
    public String toString() {
        var buffer = new SecureBuffer();
        writeTo(new JsonWriter(buffer));
        return new String(buffer.array(), 0, buffer.length(), StandardCharsets.UTF_8);
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof JsonValue value && kind == value.kind && bool == value.bool && Objects.equals(text, value.text)
                && Objects.equals(members, value.members) && Objects.equals(elements, value.elements);
    }

    @Override
    public int hashCode() {
        return Objects.hash(kind, text, bool, members, elements);
    }

    void writeTo(JsonWriter writer) {
        switch (kind) {
            case NULL -> writer.literal("null");
            case BOOLEAN -> writer.literal(bool ? "true" : "false");
            case NUMBER -> writer.literal(text);
            case STRING -> writer.value(text);
            case OBJECT -> {
                writer.beginObject();
                for (var member : members.entrySet()) {
                    writer.name(member.getKey());
                    member.getValue().writeTo(writer);
                }
                writer.endObject();
            }
            case ARRAY -> {
                writer.beginArray();
                for (var element : elements)
                    element.writeTo(writer);
                writer.endArray();
            }
        }
    }

    private void expect(Kind expected) {
        if (kind != expected)
            throw new VaultJsonException("Expected a JSON " + expected.name().toLowerCase(java.util.Locale.ROOT) + ", not " + describe() + ".");
    }

    private VaultJsonException mismatch(String expected) {
        return new VaultJsonException("Expected " + expected + ", not " + describe() + ".");
    }

    private String describe() {
        return switch (kind) {
            case NULL -> "null";
            case STRING -> "a string";
            case NUMBER -> "a number";
            case BOOLEAN -> "a boolean";
            case OBJECT -> "an object";
            case ARRAY -> "an array";
        };
    }

    // An integer, written as a JSON number or (leniently) in a string: "12", "-3", "4.0" and "1e3"
    // are integers; "4.5" isn't.
    private static long parseLong(String number) {
        try {
            return Long.parseLong(number);
        } catch (NumberFormatException e) {
            try {
                return new BigDecimal(number.strip()).longValueExact();
            } catch (NumberFormatException | ArithmeticException notInteger) {
                throw new VaultJsonException("Expected an integer that fits 64 bits; the value isn't one.");
            }
        }
    }
}
