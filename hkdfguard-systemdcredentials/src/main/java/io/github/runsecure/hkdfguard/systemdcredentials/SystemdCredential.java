package io.github.runsecure.hkdfguard.systemdcredentials;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.Utf8Utility;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * A decrypted credential's value. Close it as soon as the value has been used: that zeroes it, and
 * any read afterwards throws {@link IllegalStateException}.
 *
 * <p>The JVM can't pin an array, so a compacting collector may leave a copy of the value behind
 * (see {@code ArrayUtility}); the value is in one array the credential owns from the read on, and
 * every smaller array it outgrew while reading was zeroed.
 */
public final class SystemdCredential implements AutoCloseable {
    /** The largest credential read: systemd's own limit on a credential's size, 1 MiB. */
    public static final int MAX_LENGTH = 1024 * 1024;

    // A process's stdout is a BufferedInputStream with an 8 KiB buffer, which a read of at least
    // that many bytes bypasses: every read asks for that much, so the value goes from the pipe
    // straight into this credential's array, never through the stream's own buffer.
    static final int MIN_READ = 8 * 1024;
    private static final int INITIAL_BUFFER_LENGTH = 16 * 1024;

    private final byte[] buffer;
    private final int length;
    private volatile boolean closed;

    private SystemdCredential(byte[] buffer, int length) {
        this.buffer = buffer;
        this.length = length;
    }

    /** {@return how many bytes the value is} */
    public int getLength() {
        return length;
    }

    /**
     * The value, as a read-only view of the credential's own array - nothing is copied. Valid
     * until the credential is closed, which zeroes what it shows.
     *
     * @return the value
     * @throws IllegalStateException the credential has been closed
     */
    public ByteBuffer getValue() {
        requireOpen();
        return ByteBuffer.wrap(buffer, 0, length).slice().asReadOnlyBuffer();
    }

    /**
     * Copies the value into {@code destination}.
     *
     * @param destination where the value is written, from its start
     * @return the number of bytes written
     * @throws IllegalStateException    the credential has been closed
     * @throws IllegalArgumentException destination is too small for the value
     */
    public int copyTo(byte[] destination) {
        requireOpen();
        if (length > destination.length)
            throw new IllegalArgumentException("The credential is " + length + " bytes; result holds " + destination.length + ".");
        System.arraycopy(buffer, 0, destination, 0, length);
        return length;
    }

    /**
     * Decodes the value as UTF-8 into {@code destination}, U+FFFD for malformed input.
     *
     * @param destination where the chars are written, from its start
     * @return the number of chars written
     * @throws IllegalStateException    the credential has been closed
     * @throws IllegalArgumentException destination is too small for the value; nothing of it is left in destination
     */
    public int decodeTo(char[] destination) {
        requireOpen();
        try {
            return Utf8Utility.decode(buffer, length, destination);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("The credential doesn't fit in result's " + destination.length + " characters.", e);
        }
    }

    /** Zeroes the value. Safe to call more than once. */
    @Override
    public void close() {
        closed = true;
        ArrayUtility.zeroMemory(buffer);
    }

    private void requireOpen() {
        if (closed)
            throw new IllegalStateException("The credential has been closed.");
    }

    /**
     * Reads stream to its end, growing the array as needed and zeroing each smaller one it drops.
     *
     * @throws InvalidSecretDataException it is longer than {@link #MAX_LENGTH}
     * @throws UncheckedIOException       reading failed; what was read is zeroed
     */
    static SystemdCredential read(InputStream stream) {
        var buffer = new byte[INITIAL_BUFFER_LENGTH];
        var length = 0;
        try {
            while (true) {
                if (buffer.length - length < MIN_READ) {
                    var larger = new byte[Math.min(Math.max(buffer.length * 2, length + MIN_READ), MAX_LENGTH + MIN_READ)];
                    System.arraycopy(buffer, 0, larger, 0, length);
                    ArrayUtility.zeroMemory(buffer);
                    buffer = larger;
                }
                var read = stream.read(buffer, length, buffer.length - length);
                if (read < 0)
                    break;
                length += read;
                if (length > MAX_LENGTH)
                    throw tooLong();
            }
            return new SystemdCredential(buffer, length);
        } catch (IOException e) {
            ArrayUtility.zeroMemory(buffer);
            throw new UncheckedIOException(e);
        } catch (RuntimeException e) {
            ArrayUtility.zeroMemory(buffer);
            throw e;
        }
    }

    /**
     * Reads the file at path whole. It is read into a direct buffer of its own, then copied into the
     * credential's array and the direct buffer zeroed, so no buffer of the JDK's keeps the value.
     *
     * @throws InvalidSecretDataException it is longer than {@link #MAX_LENGTH}
     * @throws UncheckedIOException       it couldn't be read
     */
    static SystemdCredential readFile(Path path) {
        try (var channel = FileChannel.open(path, StandardOpenOption.READ)) {
            return readFile(channel);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static SystemdCredential readFile(FileChannel channel) throws IOException {
        var size = channel.size();
        if (size > MAX_LENGTH)
            throw tooLong();

        var buffer = new byte[(int) size];
        var direct = ByteBuffer.allocateDirect(Math.max(1, (int) size));
        direct.limit((int) size);
        try {
            while (direct.hasRemaining() && channel.read(direct, direct.position()) > 0) {
                // read until the end, or the file is shorter than its size said
            }
            var read = direct.position();
            direct.flip().get(buffer, 0, read);
            return new SystemdCredential(buffer, read);
        } catch (IOException | RuntimeException e) {
            ArrayUtility.zeroMemory(buffer);
            throw e;
        } finally {
            direct.clear();
            while (direct.hasRemaining())
                direct.put((byte) 0);
        }
    }

    private static InvalidSecretDataException tooLong() {
        return new InvalidSecretDataException("The credential is longer than systemd's " + MAX_LENGTH + "-byte limit.");
    }
}
