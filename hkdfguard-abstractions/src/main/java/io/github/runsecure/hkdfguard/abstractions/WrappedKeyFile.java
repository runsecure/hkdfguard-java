package io.github.runsecure.hkdfguard.abstractions;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Objects;

/**
 * Reads a wrapped-DEK key file with ordinary Java file I/O - the default
 * {@link KeyWrapper#readKeyFileAsync}, for key wrappers with no native library of their own to read
 * through (a remote KMS, say, or a test double). A wrapper backed by the native KMS library reads
 * through that library instead, which also checks who could have written the file.
 */
public final class WrappedKeyFile {
    private WrappedKeyFile() {
    }

    /**
     * Reads a wrapped DEK, refusing an empty file or one over {@link WrappedKeyLimits#MAX_BYTES}.
     * Never reads more than one byte past the limit, whatever the file's size - so a wrong path (a
     * log, a device) or a file still growing can't make startup allocate an unbounded buffer.
     *
     * @param path the key file's path
     * @return the file's contents, still wrapped
     * @throws NullPointerException    path is null
     * @throws InvalidKeyFileException the file is empty or larger than the limit
     * @throws IOException             the file can't be opened or read (a
     *                                 {@link java.nio.file.NoSuchFileException} when it doesn't exist)
     */
    public static byte[] read(Path path) throws IOException {
        Objects.requireNonNull(path, "path");

        var buffer = new byte[WrappedKeyLimits.MAX_BYTES + 1];
        var total = 0;
        try (var stream = Files.newInputStream(path)) {
            int read;
            while (total < buffer.length && (read = stream.read(buffer, total, buffer.length - total)) > 0)
                total += read;
        }

        if (total == 0)
            throw new InvalidKeyFileException("Key file '" + path + "' is empty.");
        if (total > WrappedKeyLimits.MAX_BYTES)
            throw new InvalidKeyFileException("Key file '" + path + "' is larger than " + WrappedKeyLimits.MAX_BYTES
                    + " bytes (WrappedKeyLimits.MAX_BYTES); a wrapped key never is.");

        return Arrays.copyOf(buffer, total);
    }
}
