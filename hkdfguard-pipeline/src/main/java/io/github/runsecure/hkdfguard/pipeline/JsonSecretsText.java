package io.github.runsecure.hkdfguard.pipeline;

import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * The JSON object of secrets, byte for byte as .NET's SecretPipelineWriter writes it with an
 * indented Utf8JsonWriter and relaxed escaping: each member on a line of its own, indented two
 * spaces, as {@code "name": "value"}; lines ended by the platform's line separator, as .NET's
 * Environment.NewLine ends them; no line separator after the closing brace; and an object with no
 * members written as {@code {}}. Encoded as UTF-8 without a byte order mark.
 * <p>
 * The names are ASCII letters, digits, '-', '_' and '.', and the values formatted ciphertext -
 * ASCII base64 for the default format - so relaxed escaping keeps them as they are ('+' stays
 * '+', where .NET's default escaping writes it as an escape). For text other than that, escaping
 * follows .NET's relaxed encoder as far as Java's character properties can: the quote, the
 * backslash and the controls with a short escape get it; every other control, format and separator character (but
 * the space), unassigned, private-use or surrogate code unit - so every character outside the
 * Basic Multilingual Plane, as a pair of escapes - becomes a backslash-u escape in upper-case hex;
 * everything else is written as it is. The JSON is never embedded in HTML.
 */
final class JsonSecretsText {
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    private JsonSecretsText() {
    }

    /** The object of {@code secrets}, in their map's order, as UTF-8. */
    static byte[] of(Map<String, String> secrets) {
        if (secrets.isEmpty())
            return "{}".getBytes(StandardCharsets.UTF_8);

        var newLine = System.lineSeparator();
        var json = new StringBuilder("{");
        var first = true;
        for (var secret : secrets.entrySet()) {
            if (!first)
                json.append(',');
            first = false;
            json.append(newLine).append("  ");
            string(json, secret.getKey());
            json.append(": ");
            string(json, secret.getValue());
        }
        return json.append(newLine).append('}').toString().getBytes(StandardCharsets.UTF_8);
    }

    // text as a JSON string, quoted and escaped.
    static void string(StringBuilder json, String text) {
        json.append('"');
        for (var i = 0; i < text.length(); i++) {
            var c = text.charAt(i);
            switch (c) {
                case '"' -> json.append("\\\"");
                case '\\' -> json.append("\\\\");
                case '\b' -> json.append("\\b");
                case '\f' -> json.append("\\f");
                case '\n' -> json.append("\\n");
                case '\r' -> json.append("\\r");
                case '\t' -> json.append("\\t");
                default -> {
                    if (escaped(c))
                        json.append("\\u").append(HEX[c >> 12]).append(HEX[(c >> 8) & 0xF]).append(HEX[(c >> 4) & 0xF]).append(HEX[c & 0xF]);
                    else
                        json.append(c);
                }
            }
        }
        json.append('"');
    }

    private static boolean escaped(char c) {
        if (c >= ' ' && c < 0x7F)
            return false;

        return switch (Character.getType(c)) {
            case Character.CONTROL, Character.FORMAT, Character.SURROGATE, Character.PRIVATE_USE, Character.UNASSIGNED,
                 Character.SPACE_SEPARATOR, Character.LINE_SEPARATOR, Character.PARAGRAPH_SEPARATOR -> true;
            default -> false;
        };
    }
}
