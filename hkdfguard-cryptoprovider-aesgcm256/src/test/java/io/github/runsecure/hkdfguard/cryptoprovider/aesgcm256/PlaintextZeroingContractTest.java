package io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256;

import static io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.Futures.await;
import static io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.Futures.sleep;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * CryptoProvider's contract, which DataEncryptionKey passes on to its callers: encrypt zeroes the
 * caller's plaintext before it returns, and on every path where it throws - including when no key
 * is available to encrypt with at all.
 */
class PlaintextZeroingContractTest {
    private static byte[] secret() {
        return "top secret".getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] wrapped() {
        return "wrapped".getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void encrypt_ZeroesThePlaintext_OnSuccess() {
        try (var provider = await(AesGcmCryptoProviderImpl.createAsync(new FakeKeyWrapper(), wrapped(), 60))) {
            var plaintext = secret();

            provider.encrypt(plaintext, new byte[provider.getEncryptedAllocationLength(plaintext.length)]);

            assertArrayEquals(new byte[plaintext.length], plaintext);
        }
    }

    @Test
    void encrypt_ZeroesThePlaintext_WhenEncryptionFails() {
        try (var provider = await(AesGcmCryptoProviderImpl.createAsync(new FakeKeyWrapper(), wrapped(), 60))) {
            var plaintext = secret();

            assertThrows(IllegalArgumentException.class, () -> provider.encrypt(plaintext, new byte[1])); // result too small

            assertArrayEquals(new byte[plaintext.length], plaintext);
        }
    }

    @Test
    void encrypt_ZeroesThePlaintext_WhenKeyAccessIsSuspended() {
        var wrapper = new FakeKeyWrapper();
        try (var provider = await(AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), 1, 1))) {
            wrapper.throwOnUnwrap = new CryptographicException("KEK revoked");
            sleep(1500);
            assertTrue(provider.isKeyAccessSuspended());
            var plaintext = secret();

            assertThrows(CryptographicException.class, () -> provider.encrypt(plaintext, new byte[64]));

            assertArrayEquals(new byte[plaintext.length], plaintext);
        }
    }

    @Test
    void encrypt_ZeroesThePlaintext_AfterClose() {
        var provider = await(AesGcmCryptoProviderImpl.createAsync(new FakeKeyWrapper(), wrapped(), 60));
        await(provider.closeAsync());
        var plaintext = secret();

        assertThrows(IllegalStateException.class, () -> provider.encrypt(plaintext, "aad".getBytes(StandardCharsets.UTF_8), new byte[64]));

        assertArrayEquals(new byte[plaintext.length], plaintext);
    }

    @Test
    void close_ZeroesTheWrappedPayloadAndTheRevealedKey() {
        var wrapped = wrapped();
        var provider = await(AesGcmCryptoProviderImpl.createAsync(new FakeKeyWrapper(), wrapped, 60));
        var key = provider.currentSession().key();

        provider.close();

        assertArrayEquals(new byte[wrapped.length], wrapped);
        assertArrayEquals(new byte[32], key);
    }

    @Test
    void aFailedReveal_ZeroesWhateverTheWrapperWroteIntoTheKeyBuffer() {
        var captured = new byte[1][];
        var wrapper = new FakeKeyWrapper(FakeKeyWrapper.randomKey()) {
            @Override
            public java.util.concurrent.CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
                captured[0] = result;
                super.unwrapAsync(wrapped, result);
                return java.util.concurrent.CompletableFuture.completedFuture(16); // wrong length: rejected
            }
        };

        Futures.assertFailsWith(CryptographicException.class, AesGcmCryptoProviderImpl.createAsync(wrapper, wrapped(), 60));

        assertArrayEquals(new byte[32], captured[0]);
    }
}
