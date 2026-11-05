package io.github.runsecure.hkdfguard.integration.configurationresolver;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

/**
 * Reads text and extracts the keys of configuration items delimited by the start and end sequences
 * of a {@link ConfigurationItemTokenBase}. The counterpart of .NET's {@code ConfigurationItemReader}.
 * <p>
 * Keys are trimmed of surrounding whitespace, and empty keys are skipped. A start sequence with no
 * matching end sequence is ignored, and so is a start sequence preceded by the token's
 * {@link ConfigurationItemTokenBase#getEscapeSequence() escape sequence}.
 */
public class ConfigurationItemReaderImpl implements ConfigurationItemReader {
    private static final Charset UTF_32BE = Charset.forName("UTF-32BE");
    private static final Charset UTF_32LE = Charset.forName("UTF-32LE");

    private final ConfigurationItemTokenBase token;
    private volatile List<String> keys = List.of();

    /**
     * @param token the token that defines the start and end sequences of a configuration item
     * @throws NullPointerException token is null
     */
    public ConfigurationItemReaderImpl(ConfigurationItemTokenBase token) {
        this.token = Objects.requireNonNull(token, "token");
    }

    @Override
    public List<String> keys() {
        return keys;
    }

    /**
     * {@inheritDoc}
     *
     * @throws NullPointerException stream is null
     */
    @Override
    public List<String> readKeys(InputStream stream, Charset encoding) {
        Objects.requireNonNull(stream, "stream");
        byte[] bytes;
        try {
            bytes = stream.readAllBytes();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        char[] chars = null;
        try {
            // A byte order mark takes precedence over the encoding given, as .NET's StreamReader does.
            var start = 0;
            var charset = Objects.requireNonNullElse(encoding, StandardCharsets.UTF_8);
            if (startsWith(bytes, 0x00, 0x00, 0xFE, 0xFF)) {
                charset = UTF_32BE;
                start = 4;
            } else if (startsWith(bytes, 0xFF, 0xFE, 0x00, 0x00)) {
                charset = UTF_32LE;
                start = 4;
            } else if (startsWith(bytes, 0xEF, 0xBB, 0xBF)) {
                charset = StandardCharsets.UTF_8;
                start = 3;
            } else if (startsWith(bytes, 0xFE, 0xFF)) {
                charset = StandardCharsets.UTF_16BE;
                start = 2;
            } else if (startsWith(bytes, 0xFF, 0xFE)) {
                charset = StandardCharsets.UTF_16LE;
                start = 2;
            }

            var decoder = charset.newDecoder().onMalformedInput(CodingErrorAction.REPLACE).onUnmappableCharacter(CodingErrorAction.REPLACE);
            var output = CharBuffer.allocate((int) Math.ceil((bytes.length - start) * (double) decoder.maxCharsPerByte()) + 4);
            chars = output.array();
            decoder.decode(ByteBuffer.wrap(bytes, start, bytes.length - start), output, true);
            decoder.flush(output);
            return readKeys(CharBuffer.wrap(chars, 0, output.position()));
        } finally {
            Text.zero(bytes);
            Text.zero(chars);
        }
    }

    @Override
    public List<String> readKeys(ByteBuffer utf8Text) {
        var chars = Text.decode(Objects.requireNonNull(utf8Text, "utf8Text").duplicate());
        try {
            return readKeys(CharBuffer.wrap(chars));
        } finally {
            Text.zero(chars);
        }
    }

    @Override
    public List<String> readKeys(CharSequence text) {
        Objects.requireNonNull(text, "text");
        var found = new ArrayList<String>();
        addKeys(text, found);
        return publish(found);
    }

    /**
     * {@inheritDoc}
     * <p>
     * Each text is read on its own, so an item can't start in one text and end in the next.
     *
     * @throws NullPointerException     texts is null
     * @throws IllegalArgumentException texts contains null
     */
    @Override
    public List<String> readKeys(Iterable<? extends CharSequence> texts) {
        Objects.requireNonNull(texts, "texts");
        var found = new ArrayList<String>();
        for (var text : texts) {
            if (text == null)
                throw new IllegalArgumentException("The texts cannot contain null.");
            addKeys(text, found);
        }
        return publish(found);
    }

    private List<String> publish(List<String> found) {
        var result = Collections.unmodifiableList(found);
        keys = result;
        return result;
    }

    private void addKeys(CharSequence text, List<String> found) {
        var start = token.getStartSequence();
        var end = token.getEndSequence();
        var escape = token.getEscapeSequence();
        var from = 0;

        while (true) {
            var startIndex = indexOf(text, start, from);
            if (startIndex < 0)
                return;

            var escaped = escape != null && endsWith(text, from, startIndex, escape);
            from = startIndex + start.length();
            if (escaped)
                continue;

            var endIndex = indexOf(text, end, from);
            if (endIndex < 0)
                return;

            var key = Text.trim(text, from, endIndex);
            if (!key.isEmpty())
                found.add(key);

            from = endIndex + end.length();
        }
    }

    /** The index of {@code sequence} in {@code text} at or after {@code from}, or -1. */
    static int indexOf(CharSequence text, String sequence, int from) {
        var last = text.length() - sequence.length();
        for (var i = from; i <= last; i++) {
            var j = 0;
            while (j < sequence.length() && text.charAt(i + j) == sequence.charAt(j))
                j++;
            if (j == sequence.length())
                return i;
        }
        return -1;
    }

    /** Whether {@code text[from, to)} ends with {@code sequence}. */
    static boolean endsWith(CharSequence text, int from, int to, String sequence) {
        if (to - from < sequence.length())
            return false;
        for (var j = 0; j < sequence.length(); j++)
            if (text.charAt(to - sequence.length() + j) != sequence.charAt(j))
                return false;
        return true;
    }

    private static boolean startsWith(byte[] bytes, int... prefix) {
        if (bytes.length < prefix.length)
            return false;
        for (var i = 0; i < prefix.length; i++)
            if ((bytes[i] & 0xFF) != prefix[i])
                return false;
        return true;
    }
}
