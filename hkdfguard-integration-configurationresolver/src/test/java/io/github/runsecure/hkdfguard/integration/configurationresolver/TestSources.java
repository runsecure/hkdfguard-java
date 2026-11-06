package io.github.runsecure.hkdfguard.integration.configurationresolver;

import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.DataEncryptionKeyImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Map;
import java.util.OptionalInt;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;

/** A real key ring, and plain-text sources that count what they are asked. */
final class TestSources {
    private static final SecureRandom RANDOM = new SecureRandom();

    private TestSources() {
    }

    /** A ring holding one real AES-256-GCM key as version 1, its current version. */
    static KeyRingImpl ring() {
        var dek = new byte[32];
        RANDOM.nextBytes(dek);
        var provider = AesGcmCryptoProviderImpl.createAsync(new FixedKeyWrapper(dek), "wrapped".getBytes(StandardCharsets.UTF_8), 60).join();
        var ring = new KeyRingImpl(new DefaultFormatProviderImpl());
        ring.add(1, new DataEncryptionKeyImpl(provider));
        return ring;
    }

    static String chars(ProtectedReadOnlyCache cache, String name) {
        var result = new char[cache.findMaxDecryptedLength(name).orElseThrow()];
        return new String(result, 0, cache.decrypt(name, result));
    }

    static String bytes(ProtectedReadOnlyCache cache, String name) {
        var result = new byte[cache.findMaxDecryptedLength(name).orElseThrow()];
        return new String(result, 0, cache.decrypt(name, result), StandardCharsets.UTF_8);
    }

    /**
     * A source over plain text, so a test can change a value and count lookups. Its bound is the
     * value's UTF-8 length; names match exactly.
     */
    static class PlainSource implements ProtectedReadOnlyCache {
        final Map<String, String> values = new ConcurrentHashMap<>();
        private final Map<String, Integer> decrypts = new ConcurrentHashMap<>();
        private final Map<String, Integer> lengthLookups = new ConcurrentHashMap<>();
        private String onFirstLookupName;
        private Runnable onFirstLookup;

        PlainSource with(String name, String value) {
            values.put(name, value);
            return this;
        }

        /** Runs action, once, as name's length is first looked up - before its value is read. */
        void onFirstLookup(String name, Runnable action) {
            onFirstLookupName = name;
            onFirstLookup = action;
        }

        int decryptCount(String name) {
            return decrypts.getOrDefault(name, 0);
        }

        int lengthLookupCount(String name) {
            return lengthLookups.getOrDefault(name, 0);
        }

        @Override
        public int decrypt(String name, byte[] result) {
            var value = read(name);
            if (value == null)
                return 0;
            var bytes = value.getBytes(StandardCharsets.UTF_8);
            System.arraycopy(bytes, 0, result, 0, bytes.length);
            return bytes.length;
        }

        @Override
        public int decrypt(String name, char[] result) {
            var value = read(name);
            if (value == null)
                return 0;
            value.getChars(0, value.length(), result, 0);
            return value.length();
        }

        @Override
        public OptionalInt findMaxDecryptedLength(String name) {
            lengthLookups.merge(name, 1, Integer::sum);
            if (name.equals(onFirstLookupName) && onFirstLookup != null) {
                var action = onFirstLookup;
                onFirstLookup = null;
                action.run();
            }
            var value = values.get(name);
            return value == null ? OptionalInt.empty() : OptionalInt.of(value.getBytes(StandardCharsets.UTF_8).length);
        }

        private String read(String name) {
            decrypts.merge(name, 1, Integer::sum);
            return values.get(name);
        }
    }

    /**
     * A source that, like a remote secret store's cache, must fetch a value before it has it: its
     * asynchronous members fetch, its synchronous ones count a blocking fetch for a value not yet
     * fetched. Each async lookup completes later, on another thread.
     */
    static final class RemoteSource extends PlainSource {
        private final Set<String> fetched = ConcurrentHashMap.newKeySet();
        final Set<String> blockingFetches = ConcurrentHashMap.newKeySet();
        final Set<String> asyncFetches = new HashSet<>();

        @Override
        public int decrypt(String name, byte[] result) {
            fetchBlocking(name);
            return super.decrypt(name, result);
        }

        @Override
        public int decrypt(String name, char[] result) {
            fetchBlocking(name);
            return super.decrypt(name, result);
        }

        @Override
        public OptionalInt findMaxDecryptedLength(String name) {
            fetchBlocking(name);
            return super.findMaxDecryptedLength(name);
        }

        @Override
        public CompletableFuture<OptionalInt> findMaxDecryptedLengthAsync(String name) {
            return CompletableFuture.supplyAsync(() -> {
                fetchAsync(name);
                return super.findMaxDecryptedLength(name);
            });
        }

        @Override
        public CompletableFuture<Integer> decryptAsync(String name, char[] result) {
            return CompletableFuture.supplyAsync(() -> {
                fetchAsync(name);
                return super.decrypt(name, result);
            });
        }

        @Override
        public CompletableFuture<Integer> decryptAsync(String name, byte[] result) {
            return CompletableFuture.supplyAsync(() -> {
                fetchAsync(name);
                return super.decrypt(name, result);
            });
        }

        private void fetchBlocking(String name) {
            if (values.containsKey(name) && fetched.add(name))
                blockingFetches.add(name);
        }

        private synchronized void fetchAsync(String name) {
            if (values.containsKey(name) && fetched.add(name))
                asyncFetches.add(name);
        }
    }

    /** A value provider over plain strings, as an application's provider of non-secret settings would be. */
    static final class MapValueProvider extends ValueProviderBase {
        private final Map<String, String> values;

        MapValueProvider(Map<String, String> values) {
            this.values = values;
        }

        @Override
        public ValueStatus tryGetBytes(String key, ByteBuffer destination) {
            var value = values.get(key);
            if (value == null)
                return ValueStatus.NOT_FOUND;
            var bytes = value.getBytes(StandardCharsets.UTF_8);
            if (bytes.length > destination.remaining())
                return ValueStatus.DESTINATION_TOO_SMALL;
            destination.put(bytes);
            return ValueStatus.FOUND;
        }

        @Override
        protected OptionalInt findByteCount(String key) {
            var value = values.get(key);
            return value == null ? OptionalInt.empty() : OptionalInt.of(value.getBytes(StandardCharsets.UTF_8).length);
        }
    }

    /** A KeyWrapper that always reveals the same fixed key. */
    private static final class FixedKeyWrapper implements KeyWrapper {
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

        @Override
        public CompletableFuture<byte[]> readKeyFileAsync(Path path) {
            throw new UnsupportedOperationException();
        }

        @Override
        public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
            throw new UnsupportedOperationException();
        }
    }
}
