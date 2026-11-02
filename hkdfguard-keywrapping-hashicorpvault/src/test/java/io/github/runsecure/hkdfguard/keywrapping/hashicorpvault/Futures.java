package io.github.runsecure.hkdfguard.keywrapping.hashicorpvault;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Waiting on futures in tests, with a timeout so a hang fails instead of stalling the build. */
final class Futures {
    private Futures() {
    }

    static <T> T await(CompletableFuture<T> future) {
        try {
            return future.get(10, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            throw e.getCause() instanceof RuntimeException runtime ? runtime : new RuntimeException(e.getCause());
        } catch (InterruptedException | TimeoutException e) {
            throw new AssertionError("The future did not complete.", e);
        }
    }

    /** Asserts the future fails with {@code type}, and returns that failure. */
    static <E extends Throwable> E assertFailsWith(Class<E> type, CompletableFuture<?> future) {
        try {
            future.get(10, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            return assertInstanceOf(type, e.getCause());
        } catch (CancellationException e) {
            // A future failed with a CancellationException reports it as itself, not as a cause.
            return assertInstanceOf(type, e);
        } catch (InterruptedException | TimeoutException e) {
            throw new AssertionError("The future did not complete.", e);
        }
        return fail("Expected the future to fail with " + type.getSimpleName() + ".");
    }

    static void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AssertionError(e);
        }
    }
}
