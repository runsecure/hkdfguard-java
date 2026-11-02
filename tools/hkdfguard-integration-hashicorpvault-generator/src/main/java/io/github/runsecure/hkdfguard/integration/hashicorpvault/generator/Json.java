package io.github.runsecure.hkdfguard.integration.hashicorpvault.generator;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Just enough JSON for the generator: a document read into LinkedHashMap (members in document
 * order), ArrayList, String, {@link Number} (a number's text, as written), Boolean and null, and
 * written back compactly. The generator's only inputs are the spec and its settings.
 */
final class Json {
    /** A number, kept as its JSON text so it's written back as it was read. */
    record Number(String text) {
        @Override
        public String toString() {
            return text;
        }
    }

    private final String text;
    private int position;

    private Json(String text) {
        this.text = text;
    }

    /**
     * The value text holds.
     *
     * @throws IllegalArgumentException text isn't JSON
     */
    static Object parse(String text) {
        var json = new Json(text);
        json.skipWhitespace();
        var value = json.value();
        json.skipWhitespace();
        if (json.position != text.length())
            throw json.error("Unexpected text after the value");
        return value;
    }

    /** value as compact JSON text. */
    static String write(Object value) {
        var out = new StringBuilder();
        write(out, value);
        return out.toString();
    }

    /** The string member name of object; null if it's missing or not a string. */
    static String string(Object object, String name) {
        return object instanceof Map<?, ?> map && map.get(name) instanceof String s ? s : null;
    }

    /** Whether the member name of object is true. */
    static boolean bool(Object object, String name) {
        return object instanceof Map<?, ?> map && Boolean.TRUE.equals(map.get(name));
    }

    /** object's members; empty if it isn't an object. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> members(Object object) {
        return object instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }

    /** The member name of object, if object is an object and has it; null otherwise. */
    static Object member(Object object, String name) {
        return members(object).get(name);
    }

    /** Whether object is an object with a member name, null or not. */
    static boolean has(Object object, String name) {
        return members(object).containsKey(name);
    }

    private static void write(StringBuilder out, Object value) {
        switch (value) {
            case null -> out.append("null");
            case String s -> writeString(out, s);
            case Map<?, ?> map -> {
                out.append('{');
                var first = true;
                for (var entry : map.entrySet()) {
                    if (!first)
                        out.append(',');
                    first = false;
                    writeString(out, (String) entry.getKey());
                    out.append(':');
                    write(out, entry.getValue());
                }
                out.append('}');
            }
            case List<?> list -> {
                out.append('[');
                for (var i = 0; i < list.size(); i++) {
                    if (i > 0)
                        out.append(',');
                    write(out, list.get(i));
                }
                out.append(']');
            }
            default -> out.append(value);
        }
    }

    private static void writeString(StringBuilder out, String s) {
        out.append('"');
        for (var i = 0; i < s.length(); i++) {
            var c = s.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20)
                        out.append(String.format("\\u%04x", (int) c));
                    else
                        out.append(c);
                }
            }
        }
        out.append('"');
    }

    private Object value() {
        if (position >= text.length())
            throw error("Unexpected end of text");

        var c = text.charAt(position);
        return switch (c) {
            case '{' -> object();
            case '[' -> array();
            case '"' -> string();
            case 't' -> literal("true", Boolean.TRUE);
            case 'f' -> literal("false", Boolean.FALSE);
            case 'n' -> literal("null", null);
            default -> number();
        };
    }

    private Map<String, Object> object() {
        var map = new LinkedHashMap<String, Object>();
        position++;
        skipWhitespace();
        if (peek() == '}') {
            position++;
            return map;
        }
        while (true) {
            skipWhitespace();
            if (peek() != '"')
                throw error("Expected a property name");
            var name = string();
            skipWhitespace();
            expect(':');
            skipWhitespace();
            map.put(name, value());
            skipWhitespace();
            if (peek() == ',') {
                position++;
                continue;
            }
            expect('}');
            return map;
        }
    }

    private List<Object> array() {
        var list = new ArrayList<Object>();
        position++;
        skipWhitespace();
        if (peek() == ']') {
            position++;
            return list;
        }
        while (true) {
            skipWhitespace();
            list.add(value());
            skipWhitespace();
            if (peek() == ',') {
                position++;
                continue;
            }
            expect(']');
            return list;
        }
    }

    private String string() {
        position++;
        var out = new StringBuilder();
        while (true) {
            if (position >= text.length())
                throw error("Unterminated string");
            var c = text.charAt(position++);
            if (c == '"')
                return out.toString();
            if (c < 0x20)
                throw error("Control character in a string");
            if (c != '\\') {
                out.append(c);
                continue;
            }
            if (position >= text.length())
                throw error("Unterminated escape");
            var escaped = text.charAt(position++);
            switch (escaped) {
                case '"', '\\', '/' -> out.append(escaped);
                case 'b' -> out.append('\b');
                case 'f' -> out.append('\f');
                case 'n' -> out.append('\n');
                case 'r' -> out.append('\r');
                case 't' -> out.append('\t');
                case 'u' -> {
                    if (position + 4 > text.length())
                        throw error("Short \\u escape");
                    try {
                        out.append((char) Integer.parseInt(text.substring(position, position + 4), 16));
                    } catch (NumberFormatException e) {
                        throw error("Bad \\u escape");
                    }
                    position += 4;
                }
                default -> throw error("Bad escape");
            }
        }
    }

    private Object literal(String literal, Object value) {
        if (!text.startsWith(literal, position))
            throw error("Unexpected character");
        position += literal.length();
        return value;
    }

    private Number number() {
        var start = position;
        if (peek() == '-')
            position++;
        var digits = position;
        while (position < text.length() && "0123456789.eE+-".indexOf(text.charAt(position)) >= 0)
            position++;
        if (position == digits)
            throw error("Unexpected character");
        var number = text.substring(start, position);
        try {
            new java.math.BigDecimal(number);
        } catch (NumberFormatException e) {
            throw error("Bad number");
        }
        return new Number(number);
    }

    private char peek() {
        return position < text.length() ? text.charAt(position) : '\0';
    }

    private void expect(char c) {
        if (peek() != c)
            throw error("Expected '" + c + "'");
        position++;
    }

    private void skipWhitespace() {
        while (position < text.length() && " \t\r\n".indexOf(text.charAt(position)) >= 0)
            position++;
    }

    private IllegalArgumentException error(String what) {
        return new IllegalArgumentException(what + " at character " + position + ".");
    }
}
