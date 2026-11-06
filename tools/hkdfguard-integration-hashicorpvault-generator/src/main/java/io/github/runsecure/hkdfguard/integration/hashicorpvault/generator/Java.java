package io.github.runsecure.hkdfguard.integration.hashicorpvault.generator;

import java.util.Set;
import java.util.regex.Pattern;

/** Turning the spec's names and prose into Java identifiers, literals and javadoc. */
final class Java {
    private static final Pattern NON_ALPHANUMERIC = Pattern.compile("[^A-Za-z0-9]+");
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");

    // Keywords, the literals, and - to be safe - the contextual keywords.
    private static final Set<String> KEYWORDS = Set.of(
            "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const", "continue",
            "default", "do", "double", "else", "enum", "extends", "final", "finally", "float", "for", "goto", "if",
            "implements", "import", "instanceof", "int", "interface", "long", "native", "new", "package", "private",
            "protected", "public", "return", "short", "static", "strictfp", "super", "switch", "synchronized", "this",
            "throw", "throws", "transient", "try", "void", "volatile", "while", "true", "false", "null", "var", "yield",
            "record", "sealed", "permits", "_");

    private Java() {
    }

    /**
     * name in PascalCase: split at anything but letters and digits, each part's first letter
     * capitalized - "kv-v2-read" is KvV2Read, as openapi-generator (and the .NET generator) names it.
     */
    static String pascal(String name) {
        var result = new StringBuilder();
        for (var part : NON_ALPHANUMERIC.split(name)) {
            if (!part.isEmpty())
                result.append(Character.toUpperCase(part.charAt(0))).append(part, 1, part.length());
        }

        if (result.isEmpty())
            return "Value";
        // Letters and digits only: one can't start with a digit.
        return (Character.isLetter(result.charAt(0)) ? "" : "_") + result;
    }

    /** name in camelCase, with "Value" appended if it's a keyword. */
    static String camel(String name) {
        var pascal = pascal(name);
        var camel = pascal.charAt(0) == '_' ? pascal : Character.toLowerCase(pascal.charAt(0)) + pascal.substring(1);
        return KEYWORDS.contains(camel) ? camel + "Value" : camel;
    }

    /** value as a Java string literal. */
    static String literal(String value) {
        var result = new StringBuilder("\"");
        for (var i = 0; i < value.length(); i++) {
            var c = value.charAt(i);
            switch (c) {
                case '\\' -> result.append("\\\\");
                case '"' -> result.append("\\\"");
                case '\n' -> result.append("\\n");
                case '\r' -> result.append("\\r");
                case '\t' -> result.append("\\t");
                default -> {
                    if (Character.isISOControl(c))
                        result.append(String.format("\\u%04x", (int) c));
                    else
                        result.append(c);
                }
            }
        }
        return result.append('"').toString();
    }

    /**
     * text for javadoc: whitespace collapsed to single spaces; &amp;, &lt; and &gt; escaped; and
     * '@', '\' and the "*&#47;" that would end the comment escaped too, so prose can never become a
     * tag, a unicode escape or the comment's end.
     */
    static String doc(String text) {
        var collapsed = WHITESPACE.matcher(text).replaceAll(" ").trim();
        return collapsed.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("@", "&#64;").replace("\\", "&#92;").replace("*/", "*&#47;");
    }
}
