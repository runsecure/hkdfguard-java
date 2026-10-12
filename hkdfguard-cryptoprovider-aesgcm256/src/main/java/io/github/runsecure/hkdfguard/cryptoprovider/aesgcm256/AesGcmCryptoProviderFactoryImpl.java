package io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256;

import io.github.runsecure.hkdfguard.abstractions.CryptoProvider;
import io.github.runsecure.hkdfguard.abstractions.CryptoProviderFactory;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import org.slf4j.Logger;

/**
 * Creates {@link AesGcmCryptoProviderImpl}s. Every provider logs each failed background refresh,
 * key-access suspension and resumption, and an approaching encryption limit - to the logger given
 * here, or else to {@link AesGcmCryptoProviderImpl}'s own SLF4J logger. Keep those entries visible:
 * they are how an operator learns that a KEK has been revoked or become unreachable, or that a key
 * needs rotating.
 */
public class AesGcmCryptoProviderFactoryImpl implements CryptoProviderFactory {
    private final Logger logger;

    /** A factory whose providers log through {@link AesGcmCryptoProviderImpl}'s SLF4J logger. */
    public AesGcmCryptoProviderFactoryImpl() {
        this(null);
    }

    /** @param logger handed to every provider this factory creates; null for the default logger */
    public AesGcmCryptoProviderFactoryImpl(Logger logger) {
        this.logger = logger;
    }

    @Override
    public CompletableFuture<CryptoProvider> createAsync(KeyWrapper wrapper, byte[] wrapped, int expirySeconds, Integer maxRefreshFailures) {
        return AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped, expirySeconds, maxRefreshFailures, logger)
                .thenApply(provider -> provider);
    }

    @Override
    public CompletableFuture<CryptoProvider> createEphemeralAsync(KeyWrapper wrapper, int expirySeconds, Integer maxRefreshFailures) {
        // Fail on bad arguments before asking the key wrapper to generate anything.
        Objects.requireNonNull(wrapper, "wrapper");
        AesGcmCryptoProviderImpl.validate(expirySeconds, maxRefreshFailures);

        // Sized to the same limit a key file is held to; trimmed to what generateAndWrapAsync wrote.
        var buffer = new byte[WrappedKeyLimits.MAX_BYTES];
        CompletableFuture<Integer> generated;
        try {
            generated = Objects.requireNonNull(wrapper.generateAndWrapAsync(buffer), "generateAndWrapAsync returned null");
        } catch (RuntimeException e) {
            return CompletableFuture.failedFuture(e);
        }

        return generated.thenCompose(length -> {
            if (length == null || length < 1 || length > buffer.length)
                throw new CryptographicException("Key wrapper reported " + length + " bytes of wrapped key; between 1 and "
                        + buffer.length + " are expected.");

            return createAsync(wrapper, Arrays.copyOf(buffer, length), expirySeconds, maxRefreshFailures);
        });
    }
}
