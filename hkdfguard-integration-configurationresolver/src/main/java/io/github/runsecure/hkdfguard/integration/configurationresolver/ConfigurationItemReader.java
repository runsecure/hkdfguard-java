package io.github.runsecure.hkdfguard.integration.configurationresolver;

import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.List;

/** Reads text and extracts the keys of the configuration items it contains. */
public interface ConfigurationItemReader {
    /**
     * Gets the keys extracted by the most recent read.
     *
     * @return the keys, or an empty list if nothing has been read
     */
    List<String> keys();

    /**
     * Reads the stream as text and extracts the keys of the configuration items it contains.
     *
     * @param stream   the stream to read; it is read from its current position and is left open
     * @param encoding the encoding of the stream; a byte order mark in the stream takes precedence
     * @return the trimmed keys, in the order they appear
     * @throws java.io.UncheckedIOException the stream could not be read
     */
    List<String> readKeys(InputStream stream, Charset encoding);

    /**
     * Reads the stream as UTF-8 text, unless it starts with another encoding's byte order mark, and
     * extracts the keys of the configuration items it contains.
     *
     * @param stream the stream to read; it is read from its current position and is left open
     * @return the trimmed keys, in the order they appear
     * @throws java.io.UncheckedIOException the stream could not be read
     */
    default List<String> readKeys(InputStream stream) {
        return readKeys(stream, StandardCharsets.UTF_8);
    }

    /**
     * Decodes the UTF-8 bytes as text and extracts the keys of the configuration items they contain.
     *
     * @param utf8Text the UTF-8 encoded text, from its position to its limit; the position is not
     *                 changed
     * @return the trimmed keys, in the order they appear
     */
    List<String> readKeys(ByteBuffer utf8Text);

    /**
     * Decodes the UTF-8 bytes as text and extracts the keys of the configuration items they contain.
     *
     * @param utf8Text the UTF-8 encoded text
     * @return the trimmed keys, in the order they appear
     */
    default List<String> readKeys(byte[] utf8Text) {
        return readKeys(ByteBuffer.wrap(utf8Text));
    }

    /**
     * Extracts the keys of the configuration items in the text.
     *
     * @param text the text to search
     * @return the trimmed keys, in the order they appear
     */
    List<String> readKeys(CharSequence text);

    /**
     * Extracts the keys of the configuration items in each of several texts, and keeps the keys from
     * all of them.
     *
     * @param texts the texts to search; each is read on its own
     * @return the trimmed keys, in the order they appear, text by text
     */
    List<String> readKeys(Iterable<? extends CharSequence> texts);
}
