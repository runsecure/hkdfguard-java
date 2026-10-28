package io.github.runsecure.hkdfguard.cache;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * A forward-only reader over UTF-8 JSON (RFC 8259) held in a byte array, for taking secrets out of
 * it without ever making one a String: a string token is reported by where its escaped text lies,
 * and unescaped only into an array the caller provides ({@link #copyString}). The counterpart of
 * .NET's Utf8JsonReader, as strict: no comments, trailing commas, leading zeros or unescaped control
 * characters, nesting at most {@link #MAX_DEPTH} deep, and nothing but whitespace after the root
 * value. A \\u escape must be a whole code point - a surrogate pair, never half of one. Duplicate
 * property names are reported as they are, for the caller to decide about. Malformed JSON throws
 * {@link Malformed}, which says where but never quotes it.
 */
final class JsonReader {
    /** The deepest nesting of objects and arrays read. */
    static final int MAX_DEPTH = 64;

    enum Token {
        START_OBJECT, END_OBJECT, START_ARRAY, END_ARRAY, PROPERTY_NAME, STRING, NUMBER, TRUE, FALSE, NULL
    }

    /** Malformed JSON, at {@link #position} bytes into line {@link #line} (both from 0). */
    static final class Malformed extends RuntimeException {
        private static final long serialVersionUID = 1L;

        final long position;
        final long line;

        Malformed(long position, long line) {
            super("Malformed JSON at byte " + position + " of line " + line + ".", null, false, false);
            this.position = position;
            this.line = line;
        }
    }

    private final byte[] json;
    private final int end;

    // Whether each open container is an object (true) or an array.
    private final boolean[] containers = new boolean[MAX_DEPTH];
    private int depth;

    private int position;
    private int line;
    private int lineStart;

    private Token token;
    private int tokenStart;
    private int valueStart;
    private int valueEnd;
    private boolean valueEscaped;
    private boolean rootDone;

    /** A reader over json[0, length). */
    JsonReader(byte[] json, int length) {
        this.json = json;
        this.end = length;
    }

    /** The token last read; null before the first. */
    Token token() {
        return token;
    }

    /** Where the token last read starts: a string's opening quote. */
    int tokenStart() {
        return tokenStart;
    }

    /** Where the token last read ends: just past a string's closing quote. */
    int bytesConsumed() {
        return position;
    }

    /** The length of a string's escaped text, or of a number's or literal's. */
    int valueLength() {
        return valueEnd - valueStart;
    }

    /**
     * Reads the next token.
     *
     * @return false at the end of the input, once the root value is complete (or before it starts,
     *         for empty input)
     * @throws Malformed the input isn't JSON, or holds anything but whitespace after the root value
     */
    boolean read() {
        skipWhitespace();
        if (position >= end) {
            if (token != null && !rootDone)
                throw malformed(position);
            return false;
        }
        if (rootDone)
            throw malformed(position);

        if (depth == 0) {
            readValue();
            return true;
        }

        var c = json[position];
        if (containers[depth - 1]) {
            if (token == Token.PROPERTY_NAME) {
                expect(':');
                readValue();
            } else if (c == '}') {
                close(Token.END_OBJECT);
            } else {
                if (token != Token.START_OBJECT) {
                    expect(',');
                    skipWhitespace();
                }
                if (position >= end || json[position] != '"')
                    throw malformed(position);
                readString(Token.PROPERTY_NAME);
            }
        } else {
            if (c == ']') {
                close(Token.END_ARRAY);
            } else {
                if (token != Token.START_ARRAY) {
                    expect(',');
                    skipWhitespace();
                }
                readValue();
            }
        }
        return true;
    }

    /**
     * Skips the children of the object or array just started, leaving the reader at its end; does
     * nothing after any other token.
     */
    void skip() {
        if (token != Token.START_OBJECT && token != Token.START_ARRAY)
            return;

        var target = depth - 1;
        while (depth > target)
            read();
    }

    /** Whether the string or property name just read is, unescaped, exactly text. */
    boolean valueTextEquals(String text) {
        var expected = text.getBytes(StandardCharsets.UTF_8);
        if (!valueEscaped)
            return Arrays.equals(json, valueStart, valueEnd, expected, 0, expected.length);

        var unescaped = new byte[valueLength()];
        var length = copyString(unescaped);
        return Arrays.equals(unescaped, 0, length, expected, 0, expected.length);
    }

    /**
     * Unescapes the string or property name just read into destination, which must hold at least
     * {@link #valueLength()} bytes - unescaped, a string is never longer than it is escaped.
     *
     * @return the number of bytes written
     */
    int copyString(byte[] destination) {
        if (!valueEscaped) {
            System.arraycopy(json, valueStart, destination, 0, valueEnd - valueStart);
            return valueEnd - valueStart;
        }

        var written = 0;
        for (var i = valueStart; i < valueEnd; i++) {
            var b = json[i];
            if (b != '\\') {
                destination[written++] = b;
                continue;
            }

            var escaped = json[++i];
            switch (escaped) {
                case 'b' -> destination[written++] = '\b';
                case 'f' -> destination[written++] = '\f';
                case 'n' -> destination[written++] = '\n';
                case 'r' -> destination[written++] = '\r';
                case 't' -> destination[written++] = '\t';
                case 'u' -> {
                    int codePoint = hex(i + 1);
                    i += 4;
                    if (Character.isHighSurrogate((char) codePoint)) {
                        codePoint = Character.toCodePoint((char) codePoint, (char) hex(i + 3));
                        i += 6;
                    }
                    written = writeUtf8(codePoint, destination, written);
                }
                default -> destination[written++] = escaped;
            }
        }
        return written;
    }

    /** Copies the number or literal just read, as its JSON text, into destination. */
    int copyRaw(byte[] destination) {
        System.arraycopy(json, valueStart, destination, 0, valueEnd - valueStart);
        return valueEnd - valueStart;
    }

    /**
     * The string or property name just read, as a String: only for text that isn't secret, such as
     * a property name or an error message. Invalid UTF-8 becomes U+FFFD.
     */
    String getString() {
        var unescaped = new byte[valueLength()];
        var length = copyString(unescaped);
        try {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPLACE)
                    .onUnmappableCharacter(CodingErrorAction.REPLACE)
                    .decode(ByteBuffer.wrap(unescaped, 0, length))
                    .toString();
        } catch (CharacterCodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private void readValue() {
        if (position >= end)
            throw malformed(position);

        switch (json[position]) {
            case '{' -> open(true, Token.START_OBJECT);
            case '[' -> open(false, Token.START_ARRAY);
            case '"' -> readString(Token.STRING);
            case 't' -> readLiteral("true", Token.TRUE);
            case 'f' -> readLiteral("false", Token.FALSE);
            case 'n' -> readLiteral("null", Token.NULL);
            default -> readNumber();
        }
    }

    private void open(boolean object, Token opened) {
        if (depth == MAX_DEPTH)
            throw malformed(position);

        containers[depth++] = object;
        tokenStart = position++;
        token = opened;
    }

    private void close(Token closed) {
        depth--;
        tokenStart = position++;
        token = closed;
        rootDone = depth == 0;
    }

    private void readString(Token read) {
        tokenStart = position;
        var escaped = false;
        var i = position + 1;
        while (true) {
            if (i >= end)
                throw malformed(i);

            var b = json[i];
            if (b == '"')
                break;
            if ((b & 0xFF) < 0x20)
                throw malformed(i);
            if (b == '\\') {
                escaped = true;
                i = checkEscape(i + 1);
            } else {
                i++;
            }
        }

        valueStart = tokenStart + 1;
        valueEnd = i;
        valueEscaped = escaped;
        position = i + 1;
        token = read;
        rootDone = read == Token.STRING && depth == 0;
    }

    // Checks the escape whose character is at i; returns the index just past it.
    private int checkEscape(int i) {
        if (i >= end)
            throw malformed(i);

        switch (json[i]) {
            case '"', '\\', '/', 'b', 'f', 'n', 'r', 't' -> {
                return i + 1;
            }
            case 'u' -> {
                var unit = hexOrThrow(i + 1);
                if (Character.isLowSurrogate((char) unit))
                    throw malformed(i);
                if (!Character.isHighSurrogate((char) unit))
                    return i + 5;

                // A high surrogate must be followed by an escaped low one.
                var next = i + 5;
                if (next + 1 >= end || json[next] != '\\' || json[next + 1] != 'u')
                    throw malformed(next);
                if (!Character.isLowSurrogate((char) hexOrThrow(next + 2)))
                    throw malformed(next + 1);
                return next + 6;
            }
            default -> throw malformed(i);
        }
    }

    private int hexOrThrow(int i) {
        if (i + 4 > end)
            throw malformed(Math.min(i, end));

        var value = 0;
        for (var j = i; j < i + 4; j++) {
            var digit = Character.digit(json[j], 16);
            if (digit < 0)
                throw malformed(j);
            value = value * 16 + digit;
        }
        return value;
    }

    // Four hex digits already checked by checkEscape.
    private int hex(int i) {
        var value = 0;
        for (var j = i; j < i + 4; j++)
            value = value * 16 + Character.digit(json[j], 16);
        return value;
    }

    private void readLiteral(String literal, Token read) {
        tokenStart = position;
        for (var k = 0; k < literal.length(); k++) {
            if (position + k >= end || json[position + k] != literal.charAt(k))
                throw malformed(position + k);
        }

        valueStart = position;
        valueEnd = position + literal.length();
        position = valueEnd;
        checkDelimiter();
        token = read;
        rootDone = depth == 0;
    }

    // -?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?
    private void readNumber() {
        tokenStart = position;
        var i = position;
        if (json[i] == '-')
            i++;

        if (i < end && json[i] == '0') {
            i++;
        } else {
            i = digits(i);
        }
        if (i < end && json[i] == '.')
            i = digits(i + 1);
        if (i < end && (json[i] == 'e' || json[i] == 'E')) {
            i++;
            if (i < end && (json[i] == '+' || json[i] == '-'))
                i++;
            i = digits(i);
        }

        valueStart = position;
        valueEnd = i;
        position = i;
        checkDelimiter();
        token = Token.NUMBER;
        rootDone = depth == 0;
    }

    // One or more digits from i; returns the index past them.
    private int digits(int i) {
        if (i >= end || !isDigit(json[i]))
            throw malformed(i);
        while (i < end && isDigit(json[i]))
            i++;
        return i;
    }

    private static boolean isDigit(byte b) {
        return b >= '0' && b <= '9';
    }

    // A number or literal must be followed by whitespace, a separator, a closing bracket or the end.
    private void checkDelimiter() {
        if (position >= end)
            return;

        switch (json[position]) {
            case ' ', '\t', '\n', '\r', ',', '}', ']' -> {
            }
            default -> throw malformed(position);
        }
    }

    private void expect(char c) {
        if (position >= end || json[position] != c)
            throw malformed(position);

        position++;
        skipWhitespace();
    }

    private void skipWhitespace() {
        while (position < end) {
            switch (json[position]) {
                case ' ', '\t', '\r' -> position++;
                case '\n' -> {
                    position++;
                    line++;
                    lineStart = position;
                }
                default -> {
                    return;
                }
            }
        }
    }

    private Malformed malformed(int at) {
        return new Malformed(at - lineStart, line);
    }

    private static int writeUtf8(int c, byte[] destination, int written) {
        if (c < 0x80) {
            destination[written++] = (byte) c;
        } else if (c < 0x800) {
            destination[written++] = (byte) (0xC0 | (c >> 6));
            destination[written++] = (byte) (0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            destination[written++] = (byte) (0xE0 | (c >> 12));
            destination[written++] = (byte) (0x80 | ((c >> 6) & 0x3F));
            destination[written++] = (byte) (0x80 | (c & 0x3F));
        } else {
            destination[written++] = (byte) (0xF0 | (c >> 18));
            destination[written++] = (byte) (0x80 | ((c >> 12) & 0x3F));
            destination[written++] = (byte) (0x80 | ((c >> 6) & 0x3F));
            destination[written++] = (byte) (0x80 | (c & 0x3F));
        }
        return written;
    }
}
