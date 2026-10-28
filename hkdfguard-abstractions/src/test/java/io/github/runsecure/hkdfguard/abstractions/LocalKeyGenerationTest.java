package io.github.runsecure.hkdfguard.abstractions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;

class LocalKeyGenerationTest {
    @Test
    void generateAndWrap_WrapsARandomDekOfTheGivenLengthThenZeroesIt() {
        var wrapper = new CapturingKeyWrapper();
        var result = new byte[64];

        int length = LocalKeyGeneration.generateAndWrap(wrapper, 32, result).join();

        assertEquals(32, length);
        assertEquals(32, wrapper.copy.length);
        assertFalse(ArrayUtility.isNullOrEmpty(wrapper.copy));
        assertTrue(ArrayUtility.isNullOrEmpty(wrapper.plaintext));
        assertSame(result, wrapper.result);
    }

    @Test
    void generateAndWrap_WhenWrapThrows_ZeroesTheDek() {
        var wrapper = new CapturingKeyWrapper();
        wrapper.fail = true;

        assertThrows(IllegalStateException.class, () -> LocalKeyGeneration.generateAndWrap(wrapper, 32, new byte[64]));
        assertTrue(ArrayUtility.isNullOrEmpty(wrapper.plaintext));
    }

    @Test
    void generateAndWrap_WithNullArguments_Throws() {
        var wrapper = new CapturingKeyWrapper();

        assertThrows(NullPointerException.class, () -> LocalKeyGeneration.generateAndWrap(null, 32, new byte[64]));
        assertThrows(NullPointerException.class, () -> LocalKeyGeneration.generateAndWrap(wrapper, 32, null));
    }

    // Keeps both the DEK it was handed (to see it zeroed afterwards) and a copy of its contents.
    private static final class CapturingKeyWrapper implements KeyWrapper {
        byte[] plaintext;
        byte[] copy;
        byte[] result;
        boolean fail;

        @Override
        public CompletableFuture<Integer> wrapAsync(byte[] plaintext, byte[] result) {
            this.plaintext = plaintext;
            this.copy = plaintext.clone();
            this.result = result;
            if (fail)
                throw new IllegalStateException("wrap failed");
            return CompletableFuture.completedFuture(plaintext.length);
        }

        @Override
        public CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public CompletableFuture<byte[]> readKeyFileAsync(Path path) {
            throw new UnsupportedOperationException();
        }
    }
}
