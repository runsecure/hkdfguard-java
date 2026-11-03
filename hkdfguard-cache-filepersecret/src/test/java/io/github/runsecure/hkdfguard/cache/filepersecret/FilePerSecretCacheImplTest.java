package io.github.runsecure.hkdfguard.cache.filepersecret;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import io.github.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.abstractions.ProtectedConfigurationPurpose;
import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.DataEncryptionKeyImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.securefile.KeyFileTrust;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.OptionalInt;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.event.Level;

/** FilePerSecretCacheImpl over a real folder TrustedFile accepts, with values written by a ring's protectors. */
class FilePerSecretCacheImplTest {
    private static final SecureRandom RANDOM = new SecureRandom();

    private final TrustedTempDirectory dir;
    private final List<KeyRingImpl> rings = new ArrayList<>();

    FilePerSecretCacheImplTest() throws IOException {
        dir = new TrustedTempDirectory();
    }

    @AfterEach
    void cleanUp() throws IOException {
        rings.forEach(KeyRingImpl::close);
        dir.close();
    }

    private Path folder() {
        return dir.path();
    }

    private static byte[] random(int length) {
        var bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static DataEncryptionKey newKey() {
        return new DataEncryptionKeyImpl(await(AesGcmCryptoProviderImpl.createAsync(new FixedKeyWrapper(random(32)), "wrapped".getBytes(StandardCharsets.UTF_8), 60)));
    }

    private KeyRingImpl newRing() {
        return newRing(new DefaultFormatProviderImpl());
    }

    private KeyRingImpl newRing(DefaultFormatProviderImpl format) {
        var ring = new KeyRingImpl(format);
        ring.add(1, newKey());
        rings.add(ring);
        return ring;
    }

    private FilePerSecretCacheImpl createCache(KeyRingImpl ring) throws NoSuchFileException {
        return new FilePerSecretCacheImpl(folder(), dir.trust(), ring, new DefaultFormatProviderImpl());
    }

    // Writes value to name's file, encrypted as a pipeline or deployer would: bound to that name.
    private void write(KeyRingImpl ring, String name, String value) throws IOException {
        write(ring, name, value, "");
    }

    private void write(KeyRingImpl ring, String name, String value, String suffix) throws IOException {
        Files.writeString(folder().resolve(name), ring.createProtector(ProtectedConfigurationPurpose.forKey(name)).encrypt(value) + suffix);
    }

    private static String decryptString(ProtectedReadOnlyCache cache, String name) {
        var result = new char[64];
        return new String(result, 0, cache.decrypt(name, result));
    }

    private static String text(byte[] bytes, int length) {
        return new String(bytes, 0, length, StandardCharsets.UTF_8);
    }

    private static <T> T await(CompletableFuture<T> future) {
        try {
            return future.get(10, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            throw e.getCause() instanceof RuntimeException runtime ? runtime : new RuntimeException(e.getCause());
        } catch (InterruptedException | TimeoutException e) {
            throw new AssertionError("The future did not complete.", e);
        }
    }

    /** Asserts the future fails with {@code type}, and returns that failure. */
    private static <E extends Throwable> E assertFailsWith(Class<E> type, CompletableFuture<?> future) {
        try {
            future.get(10, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            return assertInstanceOf(type, e.getCause());
        } catch (InterruptedException | TimeoutException e) {
            throw new AssertionError("The future did not complete.", e);
        }
        return fail("Expected the future to fail with " + type.getSimpleName() + ".");
    }

    @Test
    void aFile_DecryptsThroughEveryOverload() throws IOException {
        var ring = newRing();
        write(ring, "Db-Password", "value");
        var cache = createCache(ring);

        assertEquals("value", decryptString(cache, "Db-Password"));
        var bytes = new byte[16];
        assertEquals("value", text(bytes, cache.decrypt("Db-Password", bytes)));
        var max = cache.findMaxDecryptedLength("Db-Password").orElseThrow();
        assertTrue(max >= 5);

        var chars = new char[16];
        assertEquals("value", new String(chars, 0, await(cache.decryptAsync("Db-Password", chars))));
        assertEquals("value", text(bytes, await(cache.decryptAsync("Db-Password", bytes))));
        assertEquals(OptionalInt.of(max), await(cache.findMaxDecryptedLengthAsync("Db-Password")));
    }

    private static final int SECRET_COUNT = 20;

    // Non-ASCII fragments, so each secret also exercises multi-byte UTF-8 - "🔑" as a surrogate pair.
    private static final String[] NON_ASCII = {"café", "naïve", "日本語", "Ωμέγα", "🔑", "Größe"};

    // SECRET_COUNT secrets, each a random Base64 run of random length plus random non-ASCII text,
    // under names that differ only by number.
    private static Map<String, String> randomSecrets() {
        var secrets = new LinkedHashMap<String, String>();
        for (var i = 0; i < SECRET_COUNT; i++)
            secrets.put(String.format("Secret-%02d", i), Base64.getEncoder().encodeToString(random(16 + RANDOM.nextInt(113)))
                    + " " + NON_ASCII[RANDOM.nextInt(NON_ASCII.length)]
                    + " " + NON_ASCII[RANDOM.nextInt(NON_ASCII.length)]);
        return secrets;
    }

    private static final Pattern FORMATTED = Pattern.compile("^enc::v1::[A-Za-z0-9+/]+=*$");

    // Writes every secret encrypted, and checks each file holds only the formatted ciphertext:
    // ASCII Base64, with neither the secret's random text nor its non-ASCII text anywhere in it.
    private void writeAndVerifyEncrypted(KeyRingImpl ring, Map<String, String> secrets) throws IOException {
        for (var secret : secrets.entrySet()) {
            write(ring, secret.getKey(), secret.getValue());

            var onDisk = Files.readAllBytes(folder().resolve(secret.getKey()));
            for (var b : onDisk)
                assertTrue(b >= 0, "The file holds a non-ASCII byte.");
            var text = new String(onDisk, StandardCharsets.US_ASCII);
            assertTrue(FORMATTED.matcher(text).matches(), text);
            assertFalse(text.contains(secret.getValue().split(" ")[0]));
            assertFalse(new String(onDisk, StandardCharsets.ISO_8859_1).contains(
                    new String(secret.getValue().getBytes(StandardCharsets.UTF_8), StandardCharsets.ISO_8859_1)));
        }
    }

    // Checks every secret through every overload, sync and async, chars and bytes.
    private static void assertEachDecrypts(FilePerSecretCacheImpl cache, Map<String, String> secrets) {
        for (var secret : secrets.entrySet()) {
            var name = secret.getKey();
            var value = secret.getValue();
            var max = cache.findMaxDecryptedLength(name).orElseThrow();
            assertEquals(OptionalInt.of(max), await(cache.findMaxDecryptedLengthAsync(name)));
            assertTrue(max >= value.getBytes(StandardCharsets.UTF_8).length);

            var chars = new char[max];
            assertEquals(value, new String(chars, 0, cache.decrypt(name, chars)));
            assertEquals(value, new String(chars, 0, await(cache.decryptAsync(name, chars))));

            var bytes = new byte[max];
            assertEquals(value, text(bytes, cache.decrypt(name, bytes)));
            assertEquals(value, text(bytes, await(cache.decryptAsync(name, bytes))));
        }
    }

    @Test
    void twentyRandomSecrets_AreOnlyCiphertextOnDisk_AndEachDecryptsThroughEveryOverload() throws IOException {
        var ring = newRing();
        var secrets = randomSecrets();
        writeAndVerifyEncrypted(ring, secrets);

        assertEachDecrypts(createCache(ring), secrets);
    }

    @Test
    void twentyRandomSecrets_LoadedConcurrently_AreServedFromMemoryOnceTheirFilesAreGone() throws IOException {
        var ring = newRing();
        var secrets = randomSecrets();
        writeAndVerifyEncrypted(ring, secrets);
        var cache = createCache(ring);

        // Every secret's first lookup at once, half of them twice, so loads also race each other.
        var names = new ArrayList<>(secrets.keySet());
        names.addAll(names.subList(0, SECRET_COUNT / 2));
        try (var threads = Executors.newVirtualThreadPerTaskExecutor()) {
            var loads = names.stream().map(name -> CompletableFuture.supplyAsync(() -> cache.findMaxDecryptedLength(name), threads)).toList();
            for (var load : loads)
                assertTrue(await(load).orElseThrow() > 0);
        }

        for (var name : secrets.keySet())
            Files.delete(folder().resolve(name));
        try (var remaining = Files.list(folder())) {
            assertEquals(0, remaining.count());
        }

        assertEachDecrypts(cache, secrets);
    }

    @Test
    void surroundingWhitespace_IsIgnored() throws IOException {
        var ring = newRing();
        write(ring, "item", "value", "\r\n");

        assertEquals("value", decryptString(createCache(ring), "item"));
    }

    @Test
    void aFile_IsReadOnce_ThenServedFromMemory() throws IOException {
        var ring = newRing();
        var cache = createCache(ring);
        write(ring, "item", "first");
        assertEquals("first", decryptString(cache, "item"));

        write(ring, "item", "second");
        assertEquals("first", decryptString(cache, "item"));
        Files.delete(folder().resolve("item"));
        assertEquals("first", decryptString(cache, "item"));
        var chars = new char[16];
        assertEquals("first", new String(chars, 0, await(cache.decryptAsync("item", chars))));
    }

    @Test
    void aChangedFile_IsPickedUpByANewInstance() throws IOException {
        var ring = newRing();
        write(ring, "item", "first");
        assertEquals("first", decryptString(createCache(ring), "item"));

        write(ring, "item", "second");
        assertEquals("second", decryptString(createCache(ring), "item"));
    }

    @Test
    void aMissingSecret_IsntRemembered_SoAFileAddedLaterIsFound() throws IOException {
        var ring = newRing();
        var cache = createCache(ring);
        assertEquals(0, cache.decrypt("item", new byte[16]));

        write(ring, "item", "value");
        assertEquals("value", decryptString(cache, "item"));
    }

    @Test
    void aMissingOrEmptyFile_IsMissing() throws IOException {
        var ring = newRing();
        Files.writeString(folder().resolve("empty"), " \n");
        var cache = createCache(ring);

        for (var name : List.of("absent", "empty")) {
            assertEquals(0, cache.decrypt(name, new byte[16]));
            assertEquals(0, cache.decrypt(name, new char[16]));
            assertEquals(OptionalInt.empty(), cache.findMaxDecryptedLength(name));
            assertEquals(0, await(cache.decryptAsync(name, new byte[16])));
            assertEquals(0, await(cache.decryptAsync(name, new char[16])));
            assertEquals(OptionalInt.empty(), await(cache.findMaxDecryptedLengthAsync(name)));
        }
    }

    @Test
    void aFolderRemovedAfterConstruction_ReportsEverySecretMissing() throws IOException {
        var ring = newRing();
        write(ring, "item", "value");
        var cache = createCache(ring);
        dir.close();

        assertEquals(0, cache.decrypt("item", new byte[16]));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", ".hidden", "..", "../item", "sub/item", "sub\\item", "db:password", "café"})
    void aNameThatCantBeAFileName_IsMissing_WithoutReadingOutsideTheFolder(String name) throws IOException {
        var ring = newRing();
        Files.createDirectory(folder().resolve("sub"));
        write(ring, "item", "value");
        var cache = new FilePerSecretCacheImpl(folder().resolve("sub"), dir.trust(), ring, new DefaultFormatProviderImpl());

        assertFalse(FilePerSecretCacheImpl.isValidName(name));
        assertEquals(0, cache.decrypt(name, new byte[16]));
        assertEquals(0, await(cache.decryptAsync(name, new char[16])));
    }

    @Test
    void isValidName_AcceptsUpToMaxNameLength_OfLettersDigitsAndPunctuation() {
        assertTrue(FilePerSecretCacheImpl.isValidName("Db-Password_v2.txt"));
        assertTrue(FilePerSecretCacheImpl.isValidName("a".repeat(FilePerSecretCacheImpl.MAX_NAME_LENGTH)));
        assertFalse(FilePerSecretCacheImpl.isValidName("a".repeat(FilePerSecretCacheImpl.MAX_NAME_LENGTH + 1)));
        assertFalse(FilePerSecretCacheImpl.isValidName(null));
    }

    @Test
    void aFileCopiedUnderAnotherName_FailsAuthentication() throws IOException {
        var ring = newRing();
        write(ring, "admin", "secret");
        Files.copy(folder().resolve("admin"), folder().resolve("reader"));
        var cache = createCache(ring);

        assertThrows(CryptographicException.class, () -> cache.decrypt("reader", new byte[16]));
        assertThrows(CryptographicException.class, () -> cache.decrypt("reader", new char[16]));
        assertThrows(CryptographicException.class, () -> cache.findMaxDecryptedLength("reader"));
        assertFailsWith(CryptographicException.class, cache.decryptAsync("reader", new byte[16]));
        assertFailsWith(CryptographicException.class, cache.decryptAsync("reader", new char[16]));
        assertFailsWith(CryptographicException.class, cache.findMaxDecryptedLengthAsync("reader"));
    }

    @Test
    void aFileThatFailsAuthentication_IsntCached_SoAFixedFileIsReadNextTime() throws IOException {
        var ring = newRing();
        write(ring, "admin", "secret");
        Files.copy(folder().resolve("admin"), folder().resolve("reader"));
        var cache = createCache(ring);
        assertThrows(CryptographicException.class, () -> cache.decrypt("reader", new byte[16]));

        write(ring, "reader", "fixed");
        assertEquals("fixed", decryptString(cache, "reader"));
    }

    @Test
    void aFileInAnUntrustedLocation_IsRefused_AndNotCached() throws IOException {
        Assumptions.assumeFalse(dir.trust().unixUserIds().contains(0L), "Running as root, whose files are trusted.");

        var ring = newRing();
        write(ring, "item", "value");
        var untrusted = new FilePerSecretCacheImpl(folder(), KeyFileTrust.ADMINISTRATORS_ONLY, ring, new DefaultFormatProviderImpl());

        var ex = assertThrows(UncheckedIOException.class, () -> untrusted.decrypt("item", new byte[16]));
        assertInstanceOf(AccessDeniedException.class, ex.getCause());
        assertTrue(ex.getMessage().contains("not trusted"), ex.getMessage());
        var async = assertFailsWith(UncheckedIOException.class, untrusted.decryptAsync("item", new byte[16]));
        assertInstanceOf(AccessDeniedException.class, async.getCause());
        assertEquals("value", decryptString(createCache(ring), "item"));
    }

    @Test
    void aValueUnderAnOlderKeyVersion_StillDecryptsAfterRotation() throws IOException {
        var ring = newRing();
        write(ring, "item", "old");
        ring.add(2, newKey());
        write(ring, "other", "new");
        var cache = createCache(ring);

        assertTrue(Files.readString(folder().resolve("item")).startsWith("enc::v1::"));
        assertTrue(Files.readString(folder().resolve("other")).startsWith("enc::v2::"));
        assertEquals("old", decryptString(cache, "item"));
        assertEquals("new", decryptString(cache, "other"));
    }

    @Test
    void aValueUnderAKeyVersionTheRingDoesntHold_Throws() throws IOException {
        var ring = newRing();
        Files.writeString(folder().resolve("item"), new DefaultFormatProviderImpl().format(new KeyTrackingValue(7, random(40))));

        var cache = createCache(ring);
        assertThrows(NoSuchElementException.class, () -> cache.decrypt("item", new byte[64]));
    }

    @Test
    void aFileOverMaxFileLength_IsRefused() throws IOException {
        var ring = newRing();
        Files.write(folder().resolve("huge"), new byte[FilePerSecretCacheImpl.MAX_FILE_LENGTH + 1]);
        var cache = createCache(ring);

        var ex = assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("huge", new byte[16]));
        assertTrue(ex.getMessage().contains("larger than " + FilePerSecretCacheImpl.MAX_FILE_LENGTH + " bytes"), ex.getMessage());
        assertFailsWith(InvalidSecretDataException.class, cache.findMaxDecryptedLengthAsync("huge"));
    }

    @Test
    void aLargeValue_DecryptsAsCharacters() throws IOException {
        // Over the default format's limit, so ring and cache both allow longer values.
        var format = new DefaultFormatProviderImpl(16 * 1024);
        var ring = newRing(format);
        var value = "x".repeat(10_000);
        write(ring, "large", value);
        var cache = new FilePerSecretCacheImpl(folder(), dir.trust(), ring, format);

        var result = new char[value.length()];
        assertEquals(value.length(), cache.decrypt("large", result));
        assertEquals(value, new String(result));
    }

    @Test
    void asyncLookups_FailInTheFuture_NeverThrow() throws IOException {
        // Java's counterpart of .NET's cancelled-token test: the file is read on the calling
        // thread, so there is nothing to cancel, but a failure still arrives through the future.
        var cache = createCache(newRing());

        assertFailsWith(NullPointerException.class, cache.decryptAsync(null, new byte[16]));
        assertFailsWith(NullPointerException.class, cache.decryptAsync(null, new char[16]));
        assertFailsWith(NullPointerException.class, cache.findMaxDecryptedLengthAsync(null));
    }

    @Test
    void sensitiveLogging_DoesntChangeTheResult_AndLogsOnlyTheName() throws IOException {
        var ring = newRing();
        write(ring, "item", "value");
        var logger = new RecordingLogger();
        var cache = new FilePerSecretCacheImpl(folder(), dir.trust(), ring, new DefaultFormatProviderImpl(), logger);

        var original = HkdfGuardTelemetry.CACHE.isSensitiveLoggingEnabled();
        HkdfGuardTelemetry.CACHE.setSensitiveLoggingEnabled(true);
        try {
            assertEquals("value", decryptString(cache, "item"));
        } finally {
            HkdfGuardTelemetry.CACHE.setSensitiveLoggingEnabled(original);
        }

        var entries = logger.entries();
        assertEquals(1, entries.size());
        assertEquals(Level.DEBUG, entries.getFirst().level());
        assertTrue(entries.getFirst().message().contains("item"), entries.getFirst().message());
        assertFalse(entries.getFirst().message().contains("value"), entries.getFirst().message());
    }

    @Test
    void aFailedLoad_IsLoggedAsAnError() throws IOException {
        var ring = newRing();
        write(ring, "admin", "secret");
        Files.copy(folder().resolve("admin"), folder().resolve("reader"));
        var logger = new RecordingLogger();
        var cache = new FilePerSecretCacheImpl(folder(), dir.trust(), ring, new DefaultFormatProviderImpl(), logger);

        assertThrows(CryptographicException.class, () -> cache.decrypt("reader", new byte[16]));

        var entries = logger.entries();
        assertEquals(1, entries.size());
        assertEquals(Level.ERROR, entries.getFirst().level());
        assertInstanceOf(CryptographicException.class, entries.getFirst().exception());
    }

    @Test
    void constructor_ValidatesItsArguments() throws IOException {
        var ring = newRing();
        var format = new DefaultFormatProviderImpl();
        var trust = dir.trust();

        assertThrows(NullPointerException.class, () -> new FilePerSecretCacheImpl(null, trust, ring, format));
        assertThrows(IllegalArgumentException.class, () -> new FilePerSecretCacheImpl(Path.of(""), trust, ring, format));
        assertThrows(NullPointerException.class, () -> new FilePerSecretCacheImpl(folder(), null, ring, format));
        assertThrows(NullPointerException.class, () -> new FilePerSecretCacheImpl(folder(), trust, null, format));
        assertThrows(NullPointerException.class, () -> new FilePerSecretCacheImpl(folder(), trust, ring, null));
        assertThrows(NoSuchFileException.class, () -> new FilePerSecretCacheImpl(folder().resolve("absent"), trust, ring, format));
        Files.writeString(folder().resolve("a-file"), "not a folder");
        assertThrows(NoSuchFileException.class, () -> new FilePerSecretCacheImpl(folder().resolve("a-file"), trust, ring, format));
        assertEquals(folder().toAbsolutePath().normalize(), new FilePerSecretCacheImpl(folder(), trust, ring, format).getFolderPath());
    }

    @Test
    void aNullName_Throws() throws IOException {
        var cache = createCache(newRing());

        assertThrows(NullPointerException.class, () -> cache.decrypt(null, new byte[16]));
        assertThrows(NullPointerException.class, () -> cache.decrypt(null, new char[16]));
        assertThrows(NullPointerException.class, () -> cache.findMaxDecryptedLength(null));
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
