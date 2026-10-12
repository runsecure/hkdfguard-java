package io.github.runsecure.hkdfguard.springboot;

import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingBuilder;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.concurrent.CompletableFuture;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** Key wrappers standing in for the native KMS, and rings built over them. */
final class TestKeyWrappers {
    private static final SecureRandom RANDOM = new SecureRandom();

    private TestKeyWrappers() {
    }

    static byte[] randomKey() {
        var key = new byte[32];
        RANDOM.nextBytes(key);
        return key;
    }

    /** Reveals one fixed DEK for any wrapped payload, so a ring builds over a known key. */
    static final class FixedKeyWrapper implements KeyWrapper {
        private final byte[] key;

        FixedKeyWrapper(byte[] key) {
            this.key = key.clone();
        }

        @Override
        public CompletableFuture<Integer> wrapAsync(byte[] plaintext, byte[] result) {
            return CompletableFuture.failedFuture(new UnsupportedOperationException("FixedKeyWrapper only reveals."));
        }

        @Override
        public CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
            System.arraycopy(key, 0, result, 0, key.length);
            return CompletableFuture.completedFuture(key.length);
        }

        @Override
        public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
            System.arraycopy(key, 0, result, 0, key.length);
            return CompletableFuture.completedFuture(key.length);
        }
    }

    /**
     * Stands in for the native platform's wrapper in end-to-end tests: a KEK held only in this
     * instance's memory, with real AES-256-GCM wrapping (nonce | ciphertext | tag). A key file it
     * wrote is genuinely wrapped, so unwrapping a tampered payload, or one wrapped under another
     * TestKekWrapper, fails as the native library would.
     */
    static final class TestKekWrapper implements KeyWrapper {
        private static final int NONCE_SIZE = 12;
        private static final int TAG_BITS = 128;

        private final SecretKeySpec kek = new SecretKeySpec(randomKey(), "AES");

        @Override
        public CompletableFuture<Integer> wrapAsync(byte[] plaintext, byte[] result) {
            try {
                var nonce = new byte[NONCE_SIZE];
                RANDOM.nextBytes(nonce);
                var cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, kek, new GCMParameterSpec(TAG_BITS, nonce));
                System.arraycopy(nonce, 0, result, 0, NONCE_SIZE);
                return CompletableFuture.completedFuture(NONCE_SIZE + cipher.doFinal(plaintext, 0, plaintext.length, result, NONCE_SIZE));
            } catch (GeneralSecurityException e) {
                return CompletableFuture.failedFuture(new CryptographicException("Wrap failed.", e));
            }
        }

        @Override
        public CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
            try {
                var cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.DECRYPT_MODE, kek, new GCMParameterSpec(TAG_BITS, wrapped, 0, NONCE_SIZE));
                return CompletableFuture.completedFuture(cipher.doFinal(wrapped, NONCE_SIZE, wrapped.length - NONCE_SIZE, result, 0));
            } catch (GeneralSecurityException e) {
                return CompletableFuture.failedFuture(new CryptographicException("The wrapped key did not unwrap under this KEK.", e));
            }
        }

        @Override
        public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
            return CompletableFuture.failedFuture(new UnsupportedOperationException("TestKekWrapper only wraps and unwraps."));
        }
    }

    /** A ring holding {@code key} as version {@code version}, read through a one-byte key file. */
    static KeyRingImpl ringOver(byte[] key, int version, DefaultFormatProviderImpl formatProvider) {
        try {
            var keyFile = Files.createTempFile("hkdfguard-dek", ".bin");
            try {
                Files.write(keyFile, new byte[] {1});
                return new KeyRingBuilder()
                        .withKeyWrapper(new FixedKeyWrapper(key))
                        .withCryptoProviderFactory(new AesGcmCryptoProviderFactoryImpl())
                        .withFormatProvider(formatProvider)
                        .withKeyRefreshInterval(60)
                        .withKeyFile(version, keyFile)
                        .buildAsync()
                        .join();
            } finally {
                Files.delete(keyFile);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    static KeyRingImpl ring() {
        return ringOver(randomKey(), 1, new DefaultFormatProviderImpl());
    }
}
