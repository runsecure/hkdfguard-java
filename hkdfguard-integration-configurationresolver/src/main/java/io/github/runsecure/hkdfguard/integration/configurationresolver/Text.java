package io.github.runsecure.hkdfguard.integration.configurationresolver;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Text rules every part of the library shares, kept identical to .NET's so a template resolves the
 * same way in every port. Not exported.
 */
final class Text {
    /** U+FFFD in UTF-8: what .NET writes for an unpaired surrogate, and Java's encoder too, here. */
    private static final byte[] REPLACEMENT = {(byte) 0xEF, (byte) 0xBF, (byte) 0xBD};

    private Text() {
    }

    /**
     * .NET's {@code char.IsWhiteSpace}, which its {@code Trim} uses: the Unicode space, line and
     * paragraph separators, U+0009-U+000D and U+0085. Java's own {@code strip} misses U+00A0 and
     * the other no-break spaces.
     */
    public static boolean isWhiteSpace(char c) {
        return Character.isSpaceChar(c) || (c >= '\t' && c <= '\r') || c == '\u0085';
    }

    /** {@code text[from, to)} with .NET's {@code Trim}, as a String. */
    public static String trim(CharSequence text, int from, int to) {
        while (from < to && isWhiteSpace(text.charAt(from)))
            from++;
        while (to > from && isWhiteSpace(text.charAt(to - 1)))
            to--;
        return text.subSequence(from, to).toString();
    }

    /** A UTF-8 decoder that writes U+FFFD for malformed input, as .NET's does. */
    public static CharsetDecoder utf8Decoder() {
        return StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
    }

    /** A UTF-8 encoder that writes U+FFFD for an unpaired surrogate, as .NET's does. */
    public static CharsetEncoder utf8Encoder() {
        return StandardCharsets.UTF_8.newEncoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE)
                .replaceWith(REPLACEMENT);
    }

    /** The UTF-8 byte count {@link #utf8Encoder()} writes for {@code text}. */
    public static int utf8Length(CharSequence text) {
        long count = 0;
        for (var i = 0; i < text.length(); i++) {
            var c = text.charAt(i);
            if (c < 0x80)
                count++;
            else if (c < 0x800)
                count += 2;
            else if (Character.isHighSurrogate(c) && i + 1 < text.length() && Character.isLowSurrogate(text.charAt(i + 1))) {
                count += 4;
                i++;
            } else
                count += 3; // a BMP character, or an unpaired surrogate written as U+FFFD
        }
        return Math.toIntExact(count);
    }

    /**
     * Encodes {@code text} as UTF-8 at {@code destination}'s position.
     *
     * @return true, the position moved past the bytes; or false, when they don't fit, with what was
     *         written wiped and the position where it was
     */
    public static boolean tryEncode(CharSequence text, ByteBuffer destination) {
        var start = destination.position();
        var encoder = utf8Encoder();
        var input = CharBuffer.wrap(text);
        if (encoder.encode(input, destination, true).isOverflow() || encoder.flush(destination).isOverflow()) {
            zero(destination, start, destination.position());
            destination.position(start);
            return false;
        }
        return true;
    }

    /**
     * Decodes {@code utf8} at {@code destination}'s position.
     *
     * @return true, the position moved past the chars; or false, when they don't fit, with what was
     *         written wiped and the position where it was
     */
    public static boolean tryDecode(ByteBuffer utf8, CharBuffer destination) {
        var start = destination.position();
        var decoder = utf8Decoder();
        if (decoder.decode(utf8, destination, true).isOverflow() || decoder.flush(destination).isOverflow()) {
            zero(destination, start, destination.position());
            destination.position(start);
            return false;
        }
        return true;
    }

    /** Decodes {@code utf8} from its position to its limit into a new, exactly sized array, which the caller wipes. */
    public static char[] decode(ByteBuffer utf8) {
        var chars = CharBuffer.allocate(utf8.remaining()); // never more chars than bytes
        var decoder = utf8Decoder();
        decoder.decode(utf8, chars, true);
        decoder.flush(chars);
        if (chars.position() == chars.capacity())
            return chars.array();
        var result = Arrays.copyOf(chars.array(), chars.position());
        zero(chars.array());
        return result;
    }

    /** Wipes {@code buffer[from, to)}, without moving its position. */
    public static void zero(ByteBuffer buffer, int from, int to) {
        for (var i = from; i < to; i++)
            buffer.put(i, (byte) 0);
    }

    /** Wipes {@code buffer[from, to)}, without moving its position. */
    public static void zero(CharBuffer buffer, int from, int to) {
        for (var i = from; i < to; i++)
            buffer.put(i, '\0');
    }

    /** Wipes {@code array}, if there is one. */
    public static void zero(byte[] array) {
        if (array != null)
            Arrays.fill(array, (byte) 0);
    }

    /** Wipes {@code array}, if there is one. */
    public static void zero(char[] array) {
        if (array != null)
            Arrays.fill(array, '\0');
    }
}
