package io.github.runsecure.hkdfguard.integration.configurationresolver;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;

/**
 * Resolves text by replacing its configuration items, such as {@code ${Name}}, with their values.
 * <p>
 * The resolved text is written at the destination's position, up to its limit, and the position is
 * moved past it. If resolving fails, everything from the position to the limit is wiped and the
 * position is not moved.
 */
public interface ConfigurationResolver {
    /**
     * Copies {@code source} to {@code destination}, replacing each configuration item with its value.
     *
     * @param source      the text to resolve
     * @param destination the buffer that receives the resolved text; it must not overlap
     *                    {@code source}
     * @return the number of characters written
     * @throws io.github.runsecure.hkdfguard.integration.configurationresolver.DestinationTooSmallException
     *         {@code destination} is too small for the resolved text
     * @throws io.github.runsecure.hkdfguard.integration.configurationresolver.ConfigurationKeyException a
     *         configuration item's key is not allowed, has no value, leads to a cycle, or its value kept
     *         changing while it was read
     */
    int resolve(CharSequence source, CharBuffer destination);

    /**
     * Copies the UTF-8 {@code source} to {@code destination}, replacing each configuration item with
     * its UTF-8 encoded value.
     *
     * @param source      the UTF-8 text to resolve, from its position to its limit; the position is
     *                    not changed
     * @param destination the buffer that receives the resolved UTF-8 text; it must not overlap
     *                    {@code source}
     * @return the number of bytes written
     * @throws io.github.runsecure.hkdfguard.integration.configurationresolver.DestinationTooSmallException
     *         {@code destination} is too small for the resolved text
     * @throws io.github.runsecure.hkdfguard.integration.configurationresolver.ConfigurationKeyException a
     *         configuration item's key is not allowed, has no value, leads to a cycle, or its value kept
     *         changing while it was read
     */
    int resolve(ByteBuffer source, ByteBuffer destination);

    /**
     * Copies {@code source} to the start of {@code destination}, replacing each configuration item
     * with its value; the whole array is wiped if resolving fails.
     *
     * @param source      the text to resolve
     * @param destination the array that receives the resolved text
     * @return the number of characters written
     */
    default int resolve(CharSequence source, char[] destination) {
        return resolve(source, CharBuffer.wrap(destination));
    }

    /**
     * Copies the UTF-8 {@code source} to the start of {@code destination}, replacing each
     * configuration item with its UTF-8 encoded value; the whole array is wiped if resolving fails.
     *
     * @param source      the UTF-8 text to resolve
     * @param destination the array that receives the resolved UTF-8 text
     * @return the number of bytes written
     */
    default int resolve(byte[] source, byte[] destination) {
        return resolve(ByteBuffer.wrap(source), ByteBuffer.wrap(destination));
    }
}
