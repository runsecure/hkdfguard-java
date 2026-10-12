package io.github.runsecure.hkdfguard.dataencryptionkey.utilities;

import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatException;
import java.util.Base64;
import java.util.Objects;

/**
 * Base64 (RFC 4648, standard alphabet, padded) checks and conversions, with the same strictness on
 * every port: input is valid only when its length is a multiple of 4, every character is in the
 * alphabet, and '=' appears only as one or two trailing padding characters. Unlike Java's own
 * decoder, unpadded input is not accepted.
 */
public final class Base64ConversionUtility {
    private Base64ConversionUtility() {
    }

    /** True if every char is valid base64 text (an empty input is). */
    public static boolean isBase64(CharSequence base64) {
        Objects.requireNonNull(base64, "base64");
        var length = base64.length();
        if (length % 4 != 0)
            return false;

        for (var i = 0; i < length; i++) {
            var c = base64.charAt(i);
            if (c == '=') {
                // Padding: only in the last two positions, and nothing but padding after it.
                if (i < length - 2)
                    return false;
                for (var j = i + 1; j < length; j++)
                    if (base64.charAt(j) != '=')
                        return false;
                return true;
            }
            if (!isAlphabet(c))
                return false;
        }
        return true;
    }

    /** True if the bytes are base64 text encoded as ASCII. */
    public static boolean isBase64(byte[] base64) {
        Objects.requireNonNull(base64, "base64");
        var chars = new StringBuilder(base64.length);
        for (var b : base64) {
            if (b < 0)
                return false;
            chars.append((char) b);
        }
        return isBase64(chars);
    }

    /**
     * The decoded length of base64 text.
     *
     * @throws EncryptedFormatException the length is not a multiple of 4
     */
    public static int getBinaryLength(CharSequence base64) {
        if (base64.isEmpty())
            return 0;

        if (base64.length() % 4 != 0)
            throw new EncryptedFormatException("Base64 input length must be a multiple of 4.");

        var padding = 0;
        if (base64.charAt(base64.length() - 1) == '=')
            padding++;
        if (base64.charAt(base64.length() - 2) == '=')
            padding++;

        return base64.length() / 4 * 3 - padding;
    }

    /** The base64 text length for {@code data}. */
    public static int getBase64Length(byte[] data) {
        return data.length == 0 ? 0 : (data.length + 2) / 3 * 4;
    }

    /**
     * Decodes base64 text into {@code destination}.
     *
     * @return the number of bytes written
     * @throws EncryptedFormatException the input is not valid base64, or the destination is too small
     */
    public static int fromBase64(CharSequence base64, byte[] destination) {
        if (!isBase64(base64) || getBinaryLength(base64) > destination.length)
            throw new EncryptedFormatException("Input is not valid base64, or the destination buffer is too small.");

        var ascii = new byte[base64.length()];
        for (var i = 0; i < ascii.length; i++)
            ascii[i] = (byte) base64.charAt(i);
        return Base64.getDecoder().decode(ascii, destination);
    }

    /** Encodes {@code data} as a base64 string. */
    public static String toBase64String(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * Encodes {@code data} as base64 into {@code destination}, without creating a String.
     *
     * @return the number of chars written
     * @throws IllegalArgumentException the destination is too small
     */
    public static int toBase64Chars(byte[] data, char[] destination) {
        var length = getBase64Length(data);
        if (destination.length < length)
            throw new IllegalArgumentException("Destination too small.");

        var encoded = Base64.getEncoder().encode(data);
        try {
            for (var i = 0; i < encoded.length; i++)
                destination[i] = (char) encoded[i];
            return encoded.length;
        } finally {
            java.util.Arrays.fill(encoded, (byte) 0);
        }
    }

    private static boolean isAlphabet(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/';
    }
}
