package io.github.runsecure.hkdfguard.integration.configurationresolver;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.Optional;

/**
 * Provides configuration values by key.
 * <p>
 * The two writing methods write the value at the destination's position, up to its limit. When they
 * return {@link ValueStatus#FOUND}, the position has moved past the value, so the number of
 * elements written is how far it moved. Otherwise the position is where it was, and nothing usable
 * is left between it and the limit.
 */
public interface ValueProvider {
    /**
     * Gets the value for the specified key as a string.
     * <p>
     * A string cannot be cleared from memory once created. Prefer {@link #tryGetBytes} or
     * {@link #tryGetChars} for secrets.
     *
     * @param key the configuration key
     * @return the value, or empty if the key was not found
     */
    Optional<String> findValue(String key);

    /**
     * Writes the value for the specified key into {@code destination}.
     *
     * @param key         the configuration key
     * @param destination the buffer that receives the value's characters, from its position
     * @return whether the value was found and whether it fit in {@code destination}
     */
    ValueStatus tryGetChars(String key, CharBuffer destination);

    /**
     * Writes the value for the specified key as UTF-8 into {@code destination}.
     *
     * @param key         the configuration key
     * @param destination the buffer that receives the value's UTF-8 bytes, from its position
     * @return whether the value was found and whether it fit in {@code destination}
     */
    ValueStatus tryGetBytes(String key, ByteBuffer destination);
}
