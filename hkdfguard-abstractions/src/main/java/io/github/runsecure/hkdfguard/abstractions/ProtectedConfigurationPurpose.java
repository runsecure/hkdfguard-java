package io.github.runsecure.hkdfguard.abstractions;

import java.nio.CharBuffer;
import java.util.Objects;

/**
 * The single rule for binding an encrypted configuration value to the configuration key it's
 * stored under. Whoever writes a value (e.g. a pipeline via {@link PipelineDataProtector}) and
 * whoever reads it must derive the same purpose, so a value copied to a different key fails
 * authentication instead of being accepted. Keys are full configuration paths (e.g.
 * "ConnectionStrings:Admin").
 * <p>
 * The rule, which every language port implements identically: the purpose is
 * {@code "HkdfGuard.EncryptedConfiguration:" + key} with the ASCII letters a-z upper-cased and every
 * other UTF-16 code unit left exactly as it is; the AAD is that purpose's UTF-8 bytes. A key that
 * isn't valid UTF-16 (it holds an unpaired surrogate) is rejected: encoding it would substitute
 * U+FFFD, giving different keys the same AAD. It deliberately does not follow any locale's or
 * Unicode version's case rules, which no two runtimes reproduce identically.
 * <p>
 * The trade-off is one-sided and safe. Keys differing only in ASCII case share a purpose. Keys
 * differing in any other way - including non-ASCII case, such as "café" and "CAFÉ" - never do;
 * reading a value under such a variant fails authentication rather than revealing it.
 */
public final class ProtectedConfigurationPurpose {
    /** The prefix every configuration purpose starts with. */
    public static final String PREFIX = "HkdfGuard.EncryptedConfiguration";

    private ProtectedConfigurationPurpose() {
    }

    /**
     * The purpose name for a configuration key - pass to a key ring's createProtector.
     *
     * @param configurationKey the full configuration path the value is stored under
     * @throws NullPointerException     configurationKey is null
     * @throws IllegalArgumentException configurationKey is empty, or not valid UTF-16
     */
    public static String forKey(String configurationKey) {
        requireKey(configurationKey);
        // Throws on an unpaired surrogate, so a purpose is only ever made for a key aadFor accepts.
        Utf8Utility.requireWellFormed(configurationKey);
        return new String(purposeChars(configurationKey));
    }

    /**
     * The same purpose as UTF-8 bytes - the Additional Authenticated Data a value stored under
     * {@code configurationKey} is encrypted with.
     *
     * @throws NullPointerException     configurationKey is null
     * @throws IllegalArgumentException configurationKey is empty, or not valid UTF-16
     */
    public static byte[] aadFor(CharSequence configurationKey) {
        requireKey(configurationKey);
        return Utf8Utility.encodeStrict(CharBuffer.wrap(purposeChars(configurationKey)));
    }

    private static void requireKey(CharSequence configurationKey) {
        Objects.requireNonNull(configurationKey, "configurationKey");
        if (configurationKey.isEmpty())
            throw new IllegalArgumentException("The configuration key must not be empty.");
    }

    // Prefix + ':' + the key, with ASCII a-z upper-cased and everything else copied as-is.
    private static char[] purposeChars(CharSequence key) {
        var purpose = new char[PREFIX.length() + 1 + key.length()];
        PREFIX.getChars(0, PREFIX.length(), purpose, 0);
        purpose[PREFIX.length()] = ':';

        var offset = PREFIX.length() + 1;
        for (var i = 0; i < key.length(); i++) {
            var c = key.charAt(i);
            purpose[offset + i] = c >= 'a' && c <= 'z' ? (char) (c - ('a' - 'A')) : c;
        }
        return purpose;
    }
}
