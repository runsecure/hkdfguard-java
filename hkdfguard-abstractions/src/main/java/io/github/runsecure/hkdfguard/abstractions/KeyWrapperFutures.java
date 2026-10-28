package io.github.runsecure.hkdfguard.abstractions;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;

/**
 * Future plumbing shared by the network KMS key wrappers (AWS KMS, Azure Key Vault, Google Cloud
 * KMS), whose every call completes on the client's threads.
 */
public final class KeyWrapperFutures {
    private KeyWrapperFutures() {
    }

    /**
     * Ties {@code result}, the future a caller holds, to {@code call}, the client's request it is
     * waiting on: cancelling the first cancels the second.
     *
     * @return result
     */
    public static <T> CompletableFuture<T> cancelling(CompletableFuture<T> result, CompletableFuture<?> call) {
        result.whenComplete((value, error) -> {
            if (result.isCancelled())
                call.cancel(true);
        });
        return result;
    }

    /**
     * The failure itself, under any {@link CompletionException} or {@link ExecutionException} a
     * future wrapped it in.
     */
    public static Throwable unwrap(Throwable error) {
        while ((error instanceof CompletionException || error instanceof ExecutionException) && error.getCause() != null)
            error = error.getCause();
        return error;
    }
}
