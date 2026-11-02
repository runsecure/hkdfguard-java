package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Writes a request body as compact UTF-8 JSON into an array that is zeroed once the request has been
 * sent, as the generated models' {@link VaultModel#writeJson} do. A {@code char[]} is written as a
 * string without becoming a String, so a secret in one never does.
 * <p>
 * {@link #value(Object)} writes null, a String or other CharSequence, a char[], a Boolean, a
 * Number, an OffsetDateTime (RFC 3339), a Map (its keys as strings), an Iterable or Object[], a
 * {@link VaultModel}, a {@link JsonValue}, or a {@link StaticVaultToken} (in its protected form).
 * Not thread-safe.
 */
public final class JsonWriter {
    private static final int MAX_DEPTH = 64;
    private static final byte[] HEX = "0123456789abcdef".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

    private final SecureBuffer output;
    // Whether each open container is an object (true) or an array, and whether it has a member yet.
    private final boolean[] objects = new boolean[MAX_DEPTH];
    private final boolean[] started = new boolean[MAX_DEPTH];
    private int depth;
    private boolean afterName;

    JsonWriter(SecureBuffer output) {
        this.output = output;
    }

    /** Starts an object: then name, value, name, value... and {@link #endObject}. */
    public JsonWriter beginObject() {
        beforeValue();
        open(true);
        output.write('{');
        return this;
    }

    public JsonWriter endObject() {
        close(true);
        output.write('}');
        return this;
    }

    /** Starts an array: then values and {@link #endArray}. */
    public JsonWriter beginArray() {
        beforeValue();
        open(false);
        output.write('[');
        return this;
    }

    public JsonWriter endArray() {
        close(false);
        output.write(']');
        return this;
    }

    /** The next member's name, inside an object. */
    public JsonWriter name(String name) {
        Objects.requireNonNull(name, "name");
        if (depth == 0 || !objects[depth - 1] || afterName)
            throw new IllegalStateException("A name goes only inside an object, before its value.");

        if (started[depth - 1])
            output.write(',');
        started[depth - 1] = true;
        writeString(name);
        output.write(':');
        afterName = true;
        return this;
    }

    /**
     * Writes value as JSON; see the class description for the types written.
     *
     * @throws IllegalArgumentException value is of a type that isn't written, a number that isn't
     *                                  finite, text holding an unpaired surrogate, or nested more
     *                                  than 64 deep
     */
    public JsonWriter value(Object value) {
        switch (value) {
            case null -> literal("null");
            case char[] chars -> {
                beforeValue();
                writeString(chars, 0, chars.length);
            }
            case CharSequence text -> {
                beforeValue();
                writeString(text);
            }
            case Boolean b -> literal(b ? "true" : "false");
            case Number number -> literal(numberText(number));
            case OffsetDateTime time -> value(DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(time));
            case StaticVaultToken token -> value(token.toString());
            case VaultModel model -> model.writeJson(this);
            case JsonValue json -> json.writeTo(this);
            case Map<?, ?> map -> {
                beginObject();
                for (var member : map.entrySet())
                    name(String.valueOf(member.getKey())).value(member.getValue());
                endObject();
            }
            case Iterable<?> items -> {
                beginArray();
                for (var item : items)
                    value(item);
                endArray();
            }
            case Object[] items -> {
                beginArray();
                for (var item : items)
                    value(item);
                endArray();
            }
            default -> throw new IllegalArgumentException("A " + value.getClass().getName() + " can't be written as JSON.");
        }
        return this;
    }

    /** Writes a JSON literal or number as it is. */
    JsonWriter literal(String text) {
        beforeValue();
        for (var i = 0; i < text.length(); i++)
            output.write(text.charAt(i));
        return this;
    }

    private static String numberText(Number number) {
        return switch (number) {
            case Integer i -> i.toString();
            case Long l -> l.toString();
            case Short s -> s.toString();
            case Byte b -> b.toString();
            case BigInteger big -> big.toString();
            case AtomicInteger atomic -> Integer.toString(atomic.get());
            case AtomicLong atomic -> Long.toString(atomic.get());
            case BigDecimal decimal -> decimal.toString();
            default -> {
                var d = number.doubleValue();
                if (!Double.isFinite(d))
                    throw new IllegalArgumentException("JSON has no " + d + ".");
                yield d == Math.rint(d) && Math.abs(d) < 1e15 ? Long.toString((long) d) : Double.toString(d);
            }
        };
    }

    private void beforeValue() {
        if (depth == 0)
            return;
        if (objects[depth - 1]) {
            if (!afterName)
                throw new IllegalStateException("A value inside an object needs a name first.");
            afterName = false;
            return;
        }

        if (started[depth - 1])
            output.write(',');
        started[depth - 1] = true;
    }

    private void open(boolean object) {
        if (depth == MAX_DEPTH)
            throw new IllegalArgumentException("JSON nested more than " + MAX_DEPTH + " deep isn't written.");
        objects[depth] = object;
        started[depth] = false;
        depth++;
    }

    private void close(boolean object) {
        if (depth == 0 || objects[depth - 1] != object || afterName)
            throw new IllegalStateException("No open " + (object ? "object" : "array") + " to end.");
        depth--;
    }

    private void writeString(CharSequence text) {
        output.write('"');
        for (var i = 0; i < text.length(); i++)
            i = writeChar(text.charAt(i), i + 1 < text.length() ? text.charAt(i + 1) : 0, i);
        output.write('"');
    }

    private void writeString(char[] text, int start, int end) {
        output.write('"');
        for (var i = start; i < end; i++)
            i = writeChar(text[i], i + 1 < end ? text[i + 1] : 0, i);
        output.write('"');
    }

    // Writes c (and next, if they are a surrogate pair) at index i; returns the index of the last
    // char written.
    private int writeChar(char c, char next, int i) {
        if (c == '"' || c == '\\') {
            output.write('\\');
            output.write(c);
        } else if (c < 0x20) {
            output.write('\\');
            switch (c) {
                case '\n' -> output.write('n');
                case '\r' -> output.write('r');
                case '\t' -> output.write('t');
                case '\b' -> output.write('b');
                case '\f' -> output.write('f');
                default -> {
                    output.write('u');
                    output.write('0');
                    output.write('0');
                    output.write(HEX[c >> 4]);
                    output.write(HEX[c & 0xF]);
                }
            }
        } else if (c < 0x80) {
            output.write(c);
        } else if (c < 0x800) {
            output.write(0xC0 | (c >> 6));
            output.write(0x80 | (c & 0x3F));
        } else if (Character.isHighSurrogate(c) && Character.isLowSurrogate(next)) {
            var codePoint = Character.toCodePoint(c, next);
            output.write(0xF0 | (codePoint >> 18));
            output.write(0x80 | ((codePoint >> 12) & 0x3F));
            output.write(0x80 | ((codePoint >> 6) & 0x3F));
            output.write(0x80 | (codePoint & 0x3F));
            return i + 1;
        } else if (Character.isSurrogate(c)) {
            throw new IllegalArgumentException("Text holding an unpaired surrogate isn't written as JSON.");
        } else {
            output.write(0xE0 | (c >> 12));
            output.write(0x80 | ((c >> 6) & 0x3F));
            output.write(0x80 | (c & 0x3F));
        }
        return i;
    }
}
