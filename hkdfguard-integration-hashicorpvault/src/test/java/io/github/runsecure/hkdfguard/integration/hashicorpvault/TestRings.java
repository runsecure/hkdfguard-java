package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.DataEncryptionKeyImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.concurrent.CompletableFuture;

/** Real key rings of real AES-256-GCM keys, and token protectors over them. */
final class TestRings {
    private static final SecureRandom RANDOM = new SecureRandom();

    private TestRings() {
    }

    /** A ring holding one fresh key as version 1. */
    static KeyRingImpl ring() {
        var key = new byte[32];
        RANDOM.nextBytes(key);
        var ring = new KeyRingImpl(new DefaultFormatProviderImpl());
        ring.add(1, new DataEncryptionKeyImpl(Futures.await(AesGcmCryptoProviderImpl.createAsync(new FixedKeyWrapper(key),
                "wrapped".getBytes(StandardCharsets.UTF_8), 60))));
        return ring;
    }

    /** A protector for {@link VaultClient#TOKEN_PURPOSE} on a fresh ring. */
    static DataProtector protector() {
        return ring().createProtector(VaultClient.TOKEN_PURPOSE);
    }

    /** What protectedToken decrypts to with protector. */
    static String decrypt(DataProtector protector, String protectedToken) {
        var chars = new char[protector.getMaxDecryptedLength(protectedToken)];
        return new String(chars, 0, protector.decrypt(protectedToken, chars));
    }

    /** A KeyWrapper that always reveals the same fixed key. */
    static final class FixedKeyWrapper implements KeyWrapper {
        private final byte[] key;

        FixedKeyWrapper(byte[] key) {
            this.key = key;
        }

        @Override
        public CompletableFuture<Integer> wrapAsync(byte[] plaintext, byte[] result) {
            throw new UnsupportedOperationException();
        }

        @Override
        public CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
            System.arraycopy(key, 0, result, 0, key.length);
            return CompletableFuture.completedFuture(key.length);
        }

        // Test double: never reads a key file.
        @Override
        public CompletableFuture<byte[]> readKeyFileAsync(Path path) {
            return CompletableFuture.failedFuture(new UnsupportedOperationException());
        }

        @Override
        public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
            throw new UnsupportedOperationException();
        }
    }
}
