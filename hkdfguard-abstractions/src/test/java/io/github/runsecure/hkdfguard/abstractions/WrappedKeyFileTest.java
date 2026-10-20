package io.github.runsecure.hkdfguard.abstractions;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class WrappedKeyFileTest {
    @TempDir
    Path directory;

    /** A key wrapper that only implements the abstract methods, as a test double or custom KMS would. */
    private static final class MinimalKeyWrapper implements KeyWrapper {
        @Override
        public CompletableFuture<Integer> wrapAsync(byte[] plaintext, byte[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
            throw new UnsupportedOperationException();
        }
    }

    private static Throwable failureOf(CompletableFuture<?> future) {
        assertTrue(future.isDone(), "the default read completes synchronously");
        return assertThrows(ExecutionException.class, future::get).getCause();
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 132, 276, WrappedKeyLimits.MAX_BYTES})
    void read_ReturnsTheWholeFile_UpToTheLimit(int length) throws IOException {
        var content = new byte[length];
        new SecureRandom().nextBytes(content);
        var path = Files.write(directory.resolve("dek.bin"), content);

        assertArrayEquals(content, WrappedKeyFile.read(path));
    }

    @ParameterizedTest
    @ValueSource(ints = {WrappedKeyLimits.MAX_BYTES + 1, 10 * 1024 * 1024})
    void read_RefusesAFileOverTheLimit(int length) throws IOException {
        var path = Files.write(directory.resolve("big.bin"), new byte[length]);

        var thrown = assertThrows(InvalidKeyFileException.class, () -> WrappedKeyFile.read(path));

        assertTrue(thrown.getMessage().contains("larger than " + WrappedKeyLimits.MAX_BYTES + " bytes"));
        assertTrue(thrown.getMessage().contains(path.toString()));
    }

    @Test
    void read_RefusesAnEmptyFile() throws IOException {
        var path = Files.write(directory.resolve("empty.bin"), new byte[0]);

        var thrown = assertThrows(InvalidKeyFileException.class, () -> WrappedKeyFile.read(path));

        assertTrue(thrown.getMessage().contains("is empty"));
    }

    @Test
    void read_AMissingFile_IsNoSuchFile() {
        assertThrows(NoSuchFileException.class, () -> WrappedKeyFile.read(directory.resolve("missing.bin")));
    }

    @Test
    void read_RejectsANullPath() {
        assertThrows(NullPointerException.class, () -> WrappedKeyFile.read(null));
    }

    @Test
    void anInvalidKeyFile_IsAnIOException() {
        assertInstanceOf(IOException.class, new InvalidKeyFileException("bad"));
    }

    @Test
    void theDefaultKeyWrapperRead_UsesWrappedKeyFile() throws Exception {
        var content = new byte[] {1, 2, 3, 4};
        var path = Files.write(directory.resolve("dek.bin"), content);

        assertArrayEquals(content, new MinimalKeyWrapper().readKeyFileAsync(path).get());
    }

    @Test
    void theDefaultKeyWrapperRead_FailsTheFuture_RatherThanThrowing() throws IOException {
        var wrapper = new MinimalKeyWrapper();
        var empty = Files.write(directory.resolve("empty.bin"), new byte[0]);

        assertInstanceOf(InvalidKeyFileException.class, failureOf(wrapper.readKeyFileAsync(empty)));
        assertInstanceOf(NoSuchFileException.class, failureOf(wrapper.readKeyFileAsync(directory.resolve("missing.bin"))));
        assertInstanceOf(NullPointerException.class, failureOf(wrapper.readKeyFileAsync(null)));
    }
}
