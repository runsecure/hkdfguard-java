package io.github.runsecure.hkdfguard.pipeline;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Objects;

/**
 * A response body that holds a secret, read into an array of the library's own for a pipeline
 * writer to take the secret from, and zeroed by {@link #close}. The counterpart of .NET's
 * PinnedBody: the JVM can't pin an array, so a compacting collector may leave a moved copy behind,
 * which zeroing can't reach. A class, not a record: a record's equals and hashCode would compare the
 * array by identity, not by content.
 */
public final class ResponseBody implements AutoCloseable {
    /** The largest body read: far beyond any secret store's response, so a larger one is refused. */
    public static final int MAX_LENGTH = 1024 * 1024;

    private static final int INITIAL_BUFFER_LENGTH = 16 * 1024;

    private final byte[] buffer;
    private final int length;

    private ResponseBody(byte[] buffer, int length) {
        this.buffer = buffer;
        this.length = length;
    }

    /**
     * Reads body to its end into an array of its own, growing it as needed, each smaller array
     * zeroed. body is read but not closed.
     *
     * @return the body read, which the caller closes to zero it
     * @throws NullPointerException       body is null
     * @throws InvalidSecretDataException the body is {@link #MAX_LENGTH} bytes or more
     * @throws IOException                reading body failed
     */
    public static ResponseBody read(InputStream body) throws IOException {
        Objects.requireNonNull(body, "body");
        var buffer = new byte[INITIAL_BUFFER_LENGTH];
        var length = 0;
        try {
            int read;
            // Never full at the top of the loop - a full buffer grows below - so each read asks for at least one byte.
            while ((read = body.read(buffer, length, buffer.length - length)) != -1) {
                length += read;
                if (length < buffer.length)
                    continue;
                if (buffer.length >= MAX_LENGTH)
                    throw new InvalidSecretDataException("The response body is " + MAX_LENGTH + " bytes or more.");

                var larger = Arrays.copyOf(buffer, Math.min(buffer.length * 2, MAX_LENGTH));
                ArrayUtility.zeroMemory(buffer);
                buffer = larger;
            }
            return new ResponseBody(buffer, length);
        } catch (IOException | RuntimeException | Error e) {
            ArrayUtility.zeroMemory(buffer);
            throw e;
        }
    }

    /** The array the body was read into: its first {@link #length()} bytes are the body. */
    public byte[] buffer() {
        return buffer;
    }

    /** How many bytes of {@link #buffer()} the body filled. */
    public int length() {
        return length;
    }

    /** Zeroes the body. */
    @Override
    public void close() {
        ArrayUtility.zeroMemory(buffer);
    }
}
