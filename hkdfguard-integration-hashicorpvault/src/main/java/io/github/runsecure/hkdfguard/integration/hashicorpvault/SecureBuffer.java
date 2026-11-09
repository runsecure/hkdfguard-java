package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import java.io.IOException;
import java.io.InputStream;

/**
 * A growable byte array that is zeroed when it grows and when it's closed: for request and response
 * bodies, which can hold tokens and secrets. Not thread-safe.
 */
final class SecureBuffer implements AutoCloseable {
    private static final int MINIMUM_CAPACITY = 256;

    // Grown into as the body arrives: a Content-Length doesn't get to claim more memory up front.
    private static final int MAXIMUM_INITIAL_CAPACITY = 1024 * 1024;

    private byte[] buffer;
    private int length;

    SecureBuffer() {
        this(0);
    }

    /** A buffer with room for expectedLength bytes to start with (within limits); 0 or less if unknown. */
    SecureBuffer(long expectedLength) {
        buffer = new byte[Math.clamp(expectedLength, MINIMUM_CAPACITY, MAXIMUM_INITIAL_CAPACITY)];
    }

    /** The array the bytes are in: [0, {@link #length()}). Valid until the buffer next grows or is closed. */
    byte[] array() {
        return buffer;
    }

    int length() {
        return length;
    }

    void write(int b) {
        reserve(1);
        buffer[length++] = (byte) b;
    }

    void write(byte[] bytes, int offset, int count) {
        reserve(count);
        System.arraycopy(bytes, offset, buffer, length, count);
        length += count;
    }

    /** Reads stream to its end into the buffer. */
    void readFrom(InputStream stream) throws IOException {
        readFrom(stream, Integer.MAX_VALUE);
    }

    /**
     * Reads stream to its end into the buffer, unless it holds more than maxLength bytes: then stops
     * there, with at most maxLength + 1 bytes read, and returns false.
     */
    boolean readFrom(InputStream stream, int maxLength) throws IOException {
        while (true) {
            reserve((int) Math.min(8192, (long) maxLength + 1 - length));
            var read = stream.read(buffer, length, (int) Math.min(buffer.length - length, (long) maxLength + 1 - length));
            if (read < 0)
                return true;
            length += read;
            if (length > maxLength)
                return false;
        }
    }

    @Override
    public void close() {
        ArrayUtility.zeroMemory(buffer);
        length = 0;
    }

    private void reserve(int count) {
        if (buffer.length - length >= count)
            return;

        var larger = new byte[Math.max(buffer.length * 2, Math.addExact(length, count))];
        System.arraycopy(buffer, 0, larger, 0, length);
        ArrayUtility.zeroMemory(buffer);
        buffer = larger;
    }
}
