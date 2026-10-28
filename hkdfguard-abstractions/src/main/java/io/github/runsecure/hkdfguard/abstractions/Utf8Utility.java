package io.github.runsecure.hkdfguard.abstractions;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.function.ToIntFunction;

/**
 * UTF-8 conversions that write into caller-owned arrays, so secrets never pass through a String,
 * and that encode exactly as the .NET library does, so every port derives identical bytes:
 * <ul>
 * <li>{@link #encode} substitutes U+FFFD (EF BF BD) for an unpaired surrogate, as .NET's
 * Encoding.UTF8 does - not Java's default '?'.</li>
 * <li>{@link #encodeStrict} refuses an unpaired surrogate instead, for AADs and other identifiers,
 * where a substitution would give two different names the same bytes.</li>
 * <li>{@link #decode} substitutes U+FFFD for malformed input.</li>
 * </ul>
 */
public final class Utf8Utility {
    private Utf8Utility() {
    }

    /** The UTF-8 byte count of {@code text}, unpaired surrogates counted as U+FFFD (3 bytes). */
    public static int encodedLength(CharSequence text) {
        return encodedLength(text, false);
    }

    /**
     * Encodes {@code text} as UTF-8 into a new, exactly sized array, substituting U+FFFD for an
     * unpaired surrogate. The caller owns the result and should zero it once done.
     */
    public static byte[] encode(CharSequence text) {
        var bytes = new byte[encodedLength(text, false)];
        write(text, bytes, false);
        return bytes;
    }

    /**
     * Encodes {@code text} as UTF-8 into a new, exactly sized array, refusing an unpaired surrogate.
     *
     * @throws IllegalArgumentException text is not valid UTF-16
     */
    public static byte[] encodeStrict(CharSequence text) {
        var bytes = new byte[encodedLength(text, true)];
        write(text, bytes, true);
        return bytes;
    }

    /**
     * Throws if {@code text} holds an unpaired surrogate - text no UTF-8 encoding represents
     * unambiguously.
     *
     * @throws IllegalArgumentException text is not valid UTF-16
     */
    public static void requireWellFormed(CharSequence text) {
        encodedLength(text, true);
    }

    /**
     * Decodes the first {@code length} bytes of {@code bytes} into {@code destination},
     * substituting U+FFFD for malformed input.
     *
     * @return the number of chars written
     * @throws IllegalArgumentException destination is too small; the chars already written to it
     *                                  are zeroed first, so no partial plaintext is left behind
     */
    public static int decode(byte[] bytes, int length, char[] destination) {
        var decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
        var in = ByteBuffer.wrap(bytes, 0, length);
        var out = CharBuffer.wrap(destination);

        CoderResult result = decoder.decode(in, out, true);
        if (result.isOverflow() || (result = decoder.flush(out)).isOverflow()) {
            Arrays.fill(destination, 0, out.position(), '\0');
            throw new IllegalArgumentException("The destination is too small for the decoded text.");
        }
        if (result.isError()) {
            Arrays.fill(destination, 0, out.position(), '\0');
            throw new IllegalArgumentException("The input could not be decoded as UTF-8.");
        }

        return out.position();
    }

    /**
     * Decodes into {@code destination} the UTF-8 that {@code writer} - a decryption, say - writes
     * into a new {@code capacity}-byte array, then zeroes that array, so the bytes never outlive
     * the call.
     *
     * @param writer fills the array it is given, returning the number of bytes it wrote
     * @return the number of chars written
     * @throws IllegalArgumentException as {@link #decode}
     */
    public static int decodeWritten(int capacity, ToIntFunction<byte[]> writer, char[] destination) {
        var bytes = new byte[capacity];
        try {
            return decode(bytes, writer.applyAsInt(bytes), destination);
        } finally {
            ArrayUtility.zeroMemory(bytes);
        }
    }

    private static int encodedLength(CharSequence text, boolean strict) {
        var length = 0;
        var count = text.length();
        for (var i = 0; i < count; i++) {
            var c = text.charAt(i);
            if (c < 0x80) {
                length += 1;
            } else if (c < 0x800) {
                length += 2;
            } else if (Character.isHighSurrogate(c) && i + 1 < count && Character.isLowSurrogate(text.charAt(i + 1))) {
                length += 4;
                i++;
            } else if (Character.isSurrogate(c)) {
                if (strict)
                    throw unpairedSurrogate(i);
                length += 3;
            } else {
                length += 3;
            }
        }
        return length;
    }

    private static void write(CharSequence text, byte[] destination, boolean strict) {
        var position = 0;
        var count = text.length();
        for (var i = 0; i < count; i++) {
            int c = text.charAt(i);
            if (Character.isHighSurrogate((char) c) && i + 1 < count && Character.isLowSurrogate(text.charAt(i + 1))) {
                c = Character.toCodePoint((char) c, text.charAt(++i));
            } else if (Character.isSurrogate((char) c)) {
                if (strict)
                    throw unpairedSurrogate(i);
                c = 0xFFFD;
            }

            if (c < 0x80) {
                destination[position++] = (byte) c;
            } else if (c < 0x800) {
                destination[position++] = (byte) (0xC0 | (c >> 6));
                destination[position++] = (byte) (0x80 | (c & 0x3F));
            } else if (c < 0x10000) {
                destination[position++] = (byte) (0xE0 | (c >> 12));
                destination[position++] = (byte) (0x80 | ((c >> 6) & 0x3F));
                destination[position++] = (byte) (0x80 | (c & 0x3F));
            } else {
                destination[position++] = (byte) (0xF0 | (c >> 18));
                destination[position++] = (byte) (0x80 | ((c >> 12) & 0x3F));
                destination[position++] = (byte) (0x80 | ((c >> 6) & 0x3F));
                destination[position++] = (byte) (0x80 | (c & 0x3F));
            }
        }
    }

    private static IllegalArgumentException unpairedSurrogate(int index) {
        return new IllegalArgumentException("The text is not valid UTF-16: it has an unpaired surrogate at index " + index + ".");
    }
}
