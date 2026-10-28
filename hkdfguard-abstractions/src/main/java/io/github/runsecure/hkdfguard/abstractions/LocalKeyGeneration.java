package io.github.runsecure.hkdfguard.abstractions;

import java.security.SecureRandom;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;

/**
 * {@link KeyWrapper#generateAndWrapAsync} for a key wrapper whose KMS has no "generate data key"
 * (e.g. Azure Key Vault, Google Cloud KMS): the DEK is generated in this process, wrapped, and
 * zeroed - it is never returned.
 */
public final class LocalKeyGeneration {
    private static final SecureRandom RANDOM = new SecureRandom();

    private LocalKeyGeneration() {
    }

    /**
     * Generates a fresh {@code length}-byte DEK, wraps it with {@code wrapper}, and zeroes it. The
     * wrapper's {@link KeyWrapper#wrapAsync} must copy the plaintext before it returns, since the
     * DEK is zeroed as soon as it does.
     *
     * @param wrapper wraps the generated DEK
     * @param length  the DEK's length, in bytes
     * @param result  the wrapped key
     * @return as the wrapper's {@link KeyWrapper#wrapAsync}
     * @throws NullPointerException wrapper or result is null
     */
    public static CompletableFuture<Integer> generateAndWrap(KeyWrapper wrapper, int length, byte[] result) {
        Objects.requireNonNull(wrapper, "wrapper");
        Objects.requireNonNull(result, "result");
        var dek = new byte[length];
        try {
            RANDOM.nextBytes(dek);
            return wrapper.wrapAsync(dek, result);
        } finally {
            ArrayUtility.zeroMemory(dek);
        }
    }
}
