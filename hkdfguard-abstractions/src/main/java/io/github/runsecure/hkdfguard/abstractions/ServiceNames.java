package io.github.runsecure.hkdfguard.abstractions;

import java.util.Objects;

/**
 * The rule for a service name - the identity of a KEK in the native KMS library: 1 to
 * {@link #MAX_LENGTH} characters, each an ASCII letter, digit or '.', not starting with '.' and
 * never containing "..". Typically reverse-DNS, e.g. "com.example.orders". Enforced in Java before
 * any native call, so a bad name fails with a clear message instead of a native status code, and
 * is never passed across the boundary at all.
 */
public final class ServiceNames {
    /** Longest service name, in characters (each is ASCII, so also in bytes). */
    public static final int MAX_LENGTH = 128;

    private ServiceNames() {
    }

    /** True if {@code name} satisfies every rule. */
    public static boolean isValid(String name) {
        return getProblem(name) == null;
    }

    /** Why {@code name} is not a valid service name, or null if it is. */
    public static String getProblem(String name) {
        if (name == null || name.isEmpty())
            return "A service name is required.";

        if (name.length() > MAX_LENGTH)
            return "A service name is at most " + MAX_LENGTH + " characters; this one is " + name.length() + ".";

        if (name.charAt(0) == '.')
            return "A service name can't start with '.'.";

        for (var i = 0; i < name.length(); i++) {
            var c = name.charAt(i);
            if (c == '.') {
                if (i > 0 && name.charAt(i - 1) == '.')
                    return "A service name can't contain '..'.";
            } else if (!isAsciiLetterOrDigit(c)) {
                return String.format("A service name may contain only ASCII letters, digits and '.'; it has U+%04X at position %d.", (int) c, i);
            }
        }

        return null;
    }

    /**
     * Throws if {@code name} is not a valid service name.
     *
     * @param name      the candidate service name
     * @param paramName the parameter name reported in the exception
     * @throws NullPointerException     name is null
     * @throws IllegalArgumentException name breaks a rule; the message says which
     */
    public static void requireValid(String name, String paramName) {
        Objects.requireNonNull(name, paramName);

        var problem = getProblem(name);
        if (problem != null)
            throw new IllegalArgumentException(paramName + ": " + problem);
    }

    private static boolean isAsciiLetterOrDigit(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
    }
}
