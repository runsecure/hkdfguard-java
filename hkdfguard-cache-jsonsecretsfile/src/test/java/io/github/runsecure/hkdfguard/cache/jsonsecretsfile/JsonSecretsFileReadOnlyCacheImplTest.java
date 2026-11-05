package io.github.runsecure.hkdfguard.cache.jsonsecretsfile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatException;
import io.github.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import io.github.runsecure.hkdfguard.abstractions.ProtectedConfigurationPurpose;
import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderImpl;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmPipelineDataProtectorImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.DataEncryptionKeyImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.pipeline.SecretPipelineWriterBase;
import io.github.runsecure.hkdfguard.pipeline.SecretRequest;
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
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.event.Level;

/**
 * JsonSecretsFileReadOnlyCacheImpl over a real file TrustedFile accepts, with values written by a
 * ring's protectors or a pipeline.
 */
class JsonSecretsFileReadOnlyCacheImplTest {
    private static final SecureRandom RANDOM = new SecureRandom();

    private final TrustedTempDirectory dir;
    private final List<KeyRingImpl> rings = new ArrayList<>();

    JsonSecretsFileReadOnlyCacheImplTest() throws IOException {
        dir = new TrustedTempDirectory();
    }

    @AfterEach
    void cleanUp() throws IOException {
        rings.forEach(KeyRingImpl::close);
        dir.close();
    }

    private Path filePath() {
        return dir.path().resolve("secrets.json");
    }

    private static byte[] random(int length) {
        var bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static DataEncryptionKey newKey(byte[] key) {
        return new DataEncryptionKeyImpl(await(AesGcmCryptoProviderImpl.createAsync(new FixedKeyWrapper(key), "wrapped".getBytes(StandardCharsets.UTF_8), 60)));
    }

    private KeyRingImpl newRing() {
        return newRing(new DefaultFormatProviderImpl(), random(32));
    }

    private KeyRingImpl newRing(DefaultFormatProviderImpl format, byte[] key) {
        var ring = new KeyRingImpl(format);
        ring.add(1, newKey(key));
        rings.add(ring);
        return ring;
    }

    private JsonSecretsFileReadOnlyCacheImpl createCache(KeyRingImpl ring) throws NoSuchFileException {
        return new JsonSecretsFileReadOnlyCacheImpl(filePath(), dir.trust(), ring, new DefaultFormatProviderImpl());
    }

    private JsonSecretsFileReadOnlyCacheImpl createCache(KeyRingImpl ring, int maxFileLength, RecordingLogger logger) throws NoSuchFileException {
        return new JsonSecretsFileReadOnlyCacheImpl(filePath(), dir.trust(), ring, new DefaultFormatProviderImpl(), maxFileLength, logger);
    }

    private static String encrypt(KeyRingImpl ring, String name, String value) {
        return ring.createProtector(ProtectedConfigurationPurpose.forKey(name)).encrypt(value);
    }

    // One JSON object of each name to its value; the values are ciphertext, so need no escaping.
    private static String json(Map<String, String> members) {
        var json = new StringBuilder("{");
        for (var member : members.entrySet())
            json.append(json.length() > 1 ? "," : "").append('"').append(member.getKey()).append("\":\"").append(member.getValue()).append('"');
        return json.append('}').toString();
    }

    // Writes each secret encrypted for its name, as one JSON object.
    private void write(KeyRingImpl ring, String... namesAndValues) throws IOException {
        var members = new LinkedHashMap<String, String>();
        for (var i = 0; i < namesAndValues.length; i += 2)
            members.put(namesAndValues[i], encrypt(ring, namesAndValues[i], namesAndValues[i + 1]));
        writeRaw(json(members));
    }

    private void writeRaw(String json) throws IOException {
        Files.writeString(filePath(), json);
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
    void whatAPipelineWrites_DecryptsUnderTheKeyItWraps() throws IOException {
        try (var protector = new AesGcmPipelineDataProtectorImpl(new DefaultFormatProviderImpl(), 1);
             var writer = new InMemoryWriter(protector, Map.of("db-password", "pässwörd", "api-key", "key"))) {
            await(writer.pullSecretsAsync());
            writer.writeJsonSecrets(filePath());

            // What the application holds once the pipeline's key has been wrapped and unwrapped.
            var ring = newRing(new DefaultFormatProviderImpl(), Base64.getDecoder().decode(protector.getKeyAsBase64().toString()));
            var cache = createCache(ring);

            assertEquals("pässwörd", decryptString(cache, "db-password"));
            assertEquals("key", decryptString(cache, "api-key"));
        }
    }

    @Test
    void aValue_DecryptsThroughEveryOverload_UnderItsNameIgnoringAsciiCase() throws IOException {
        var ring = newRing();
        write(ring, "Db-Password", "value");
        var cache = createCache(ring);

        assertEquals("value", decryptString(cache, "Db-Password"));
        assertEquals("value", decryptString(cache, "DB-PASSWORD"));
        var bytes = new byte[16];
        assertEquals("value", text(bytes, cache.decrypt("db-password", bytes)));
        var max = cache.findMaxDecryptedLength("Db-Password").orElseThrow();
        assertTrue(max >= 5);

        var chars = new char[16];
        assertEquals("value", new String(chars, 0, await(cache.decryptAsync("Db-Password", chars))));
        assertEquals("value", text(bytes, await(cache.decryptAsync("Db-Password", bytes))));
        assertEquals(OptionalInt.of(max), await(cache.findMaxDecryptedLengthAsync("Db-Password")));
    }

    @Test
    void theFile_IsReadOnce_EvenByConcurrentLookups_ThenServedFromMemory() throws IOException {
        var ring = newRing();
        var members = new LinkedHashMap<String, String>();
        for (var i = 0; i < 200; i++)
            members.put(String.format("secret-%03d", i), encrypt(ring, String.format("secret-%03d", i), "value-" + i));
        writeRaw(json(members));
        var cache = createCache(ring);

        List<CompletableFuture<String>> lookups;
        try (var threads = Executors.newVirtualThreadPerTaskExecutor()) {
            lookups = members.keySet().stream().map(name -> CompletableFuture.supplyAsync(() -> decryptString(cache, name), threads)).toList();
        }
        Files.delete(filePath());

        for (var i = 0; i < 200; i++)
            assertEquals("value-" + i, await(lookups.get(i)));
        assertEquals("value-7", decryptString(cache, "secret-007"));
    }

    @Test
    void theFile_IsLoadedOnce_AsOneSpanOfWork() throws IOException {
        var ring = newRing();
        write(ring, "item", "first", "other", "second");
        var logger = new RecordingLogger();
        var cache = createCache(ring, JsonSecretsFileReadOnlyCacheImpl.DEFAULT_MAX_FILE_LENGTH, logger);

        var original = HkdfGuardTelemetry.CACHE.isSensitiveLoggingEnabled();
        HkdfGuardTelemetry.CACHE.setSensitiveLoggingEnabled(true);
        try {
            assertEquals("first", decryptString(cache, "item"));
            assertEquals("second", decryptString(cache, "other"));
        } finally {
            HkdfGuardTelemetry.CACHE.setSensitiveLoggingEnabled(original);
        }

        // Each lookup's name, and the one load's path - never a value.
        var messages = logger.entries().stream().map(RecordingLogger.Entry::message).toList();
        assertEquals(3, messages.size(), messages.toString());
        assertEquals(1, messages.stream().filter(m -> m.contains(cache.getFilePath().toString())).count(), messages.toString());
        assertTrue(messages.stream().noneMatch(m -> m.contains("first") || m.contains("second")), messages.toString());
        assertTrue(logger.entries().stream().allMatch(e -> e.level() == Level.DEBUG));
    }

    @Test
    void aChangedFile_IsPickedUpByANewInstance() throws IOException {
        var ring = newRing();
        write(ring, "item", "first");
        var cache = createCache(ring);
        assertEquals("first", decryptString(cache, "item"));

        write(ring, "item", "second");
        assertEquals("first", decryptString(cache, "item"));
        assertEquals("second", decryptString(createCache(ring), "item"));
    }

    @ParameterizedTest
    @CsvSource(value = {"absent", "''", ".hidden", "../item", "ıtem", "it em", "ítem"}, emptyValue = "")
    void aNameTheFileDoesntHold_OrThatCantBeOne_IsMissing(String name) throws IOException {
        var ring = newRing();
        write(ring, "item", "value");
        var cache = createCache(ring);

        assertEquals(0, cache.decrypt(name, new byte[16]));
        assertEquals(0, await(cache.decryptAsync(name, new byte[16])));
        assertEquals(0, cache.decrypt(name, new char[16]));
        assertEquals(0, await(cache.decryptAsync(name, new char[16])));
        assertEquals(OptionalInt.empty(), cache.findMaxDecryptedLength(name));
        assertEquals(OptionalInt.empty(), await(cache.findMaxDecryptedLengthAsync(name)));
    }

    @Test
    void aMissingFile_ReportsEverySecretMissing_AndIsntRemembered() throws IOException {
        var ring = newRing();
        write(ring, "item", "value");
        var cache = createCache(ring);
        Files.delete(filePath());

        assertEquals(0, cache.decrypt("item", new byte[16]));
        assertEquals(0, await(cache.decryptAsync("item", new char[16])));

        write(ring, "item", "later");
        assertEquals("later", decryptString(cache, "item"));
    }

    @Test
    void aFolderRemovedAfterConstruction_ReportsEverySecretMissing() throws IOException {
        var ring = newRing();
        var folder = Files.createDirectory(dir.path().resolve("sub"));
        var path = folder.resolve("secrets.json");
        Files.writeString(path, json(Map.of("item", encrypt(ring, "item", "value"))));
        var cache = new JsonSecretsFileReadOnlyCacheImpl(path, dir.trust(), ring, new DefaultFormatProviderImpl());
        Files.delete(path);
        Files.delete(folder);

        assertEquals(0, cache.decrypt("item", new byte[16]));
    }

    static Stream<Arguments> filesThatArentTheSecretsObject() {
        return Stream.of(
                Arguments.of("", "valid JSON"),
                Arguments.of("  \n ", "valid JSON"),
                Arguments.of("not json", "valid JSON"),
                Arguments.of("[\"item\"]", "not an object of secrets"),
                Arguments.of("\"item\"", "not an object of secrets"),
                Arguments.of("{\"item\":1}", "no value for 'item'"),
                Arguments.of("{\"item\":{\"a\":\"b\"}}", "no value for 'item'"),
                Arguments.of("{\"item\":null}", "no value for 'item'"),
                Arguments.of("{\"item\":\"  \"}", "no value for 'item'"),
                Arguments.of("{\"../item\":\"x\"}", "isn't a secret's name"),
                Arguments.of("{\"\":\"x\"}", "isn't a secret's name"),
                Arguments.of("{\"item\":\"{0}\",\"ITEM\":\"{0}\"}", "'ITEM' more than once"),
                Arguments.of("{\"item\":\"{0}\"} {}", "valid JSON"),
                Arguments.of("{\"item\":\"{0}\" ", "valid JSON"),
                // A byte order mark, which .NET's reader refuses too.
                Arguments.of("\uFEFF{\"item\":\"{0}\"}", "valid JSON"));
    }

    @ParameterizedTest
    @MethodSource("filesThatArentTheSecretsObject")
    void aFileThatIsntTheSecretsObject_IsRefused_AndNotKept(String json, String problem) throws IOException {
        var ring = newRing();
        writeRaw(json.replace("{0}", encrypt(ring, "item", "value")));
        var cache = createCache(ring);

        var e = assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("item", new byte[16]));
        assertTrue(e.getMessage().contains(problem), e.getMessage());
        assertTrue(e.getMessage().contains(cache.getFilePath().toString()), e.getMessage());
        assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("item", new char[16]));
        assertFailsWith(InvalidSecretDataException.class, cache.decryptAsync("item", new byte[16]));

        write(ring, "item", "fixed");
        assertEquals("fixed", decryptString(cache, "item"));
    }

    @Test
    void aFileThatIsntUtf8_IsRefused() throws IOException {
        var ring = newRing();
        Files.write(filePath(), new byte[] {'{', '"', (byte) 0xFF, '"', ':', '"', 'x', '"', '}'});

        var e = assertThrows(InvalidSecretDataException.class, () -> createCache(ring).decrypt("item", new byte[16]));
        assertTrue(e.getMessage().contains("isn't UTF-8"), e.getMessage());
    }

    @Test
    void aValueThatIsntAFormattedValue_IsRefusedByTheFormat() throws IOException {
        var ring = newRing();
        writeRaw(json(Map.of("item", "plain text")));

        assertThrows(EncryptedFormatException.class, () -> createCache(ring).decrypt("item", new byte[16]));
    }

    @Test
    void aValueMovedUnderAnotherName_FailsTheWholeFile() throws IOException {
        var ring = newRing();
        var members = new LinkedHashMap<String, String>();
        members.put("reader", encrypt(ring, "reader", "fine"));
        members.put("writer", encrypt(ring, "reader", "moved"));
        writeRaw(json(members));
        var logger = new RecordingLogger();
        var cache = createCache(ring, JsonSecretsFileReadOnlyCacheImpl.DEFAULT_MAX_FILE_LENGTH, logger);

        assertThrows(CryptographicException.class, () -> cache.decrypt("reader", new byte[16]));
        assertFailsWith(CryptographicException.class, cache.decryptAsync("reader", new char[16]));
        assertThrows(CryptographicException.class, () -> cache.findMaxDecryptedLength("reader"));

        // Each failed load, logged as an error.
        var entries = logger.entries();
        assertEquals(3, entries.size());
        assertEquals(Level.ERROR, entries.getFirst().level());
        assertInstanceOf(CryptographicException.class, entries.getFirst().exception());
    }

    @Test
    void aValueUnderAKeyVersionTheRingDoesntHold_FailsTheWholeFile() throws IOException {
        var ring = newRing();
        var members = new LinkedHashMap<String, String>();
        members.put("item", encrypt(ring, "item", "fine"));
        members.put("old", new DefaultFormatProviderImpl().format(new KeyTrackingValue(7, random(40))));
        writeRaw(json(members));

        assertThrows(NoSuchElementException.class, () -> createCache(ring).decrypt("item", new byte[16]));
    }

    @Test
    void valuesUnderOlderKeyVersions_StillDecryptAfterRotation() throws IOException {
        var ring = newRing();
        var old = encrypt(ring, "item", "old");
        ring.add(2, newKey(random(32)));
        writeRaw(json(Map.of("item", old, "other", encrypt(ring, "other", "new"))));
        var cache = createCache(ring);

        assertTrue(old.startsWith("enc::v1::"));
        assertEquals("old", decryptString(cache, "item"));
        assertEquals("new", decryptString(cache, "other"));
    }

    @Test
    void aFileInAnUntrustedLocation_IsRefused_AndNotKept() throws IOException {
        Assumptions.assumeFalse(dir.trust().unixUserIds().contains(0L), "Running as root, whose files are trusted.");

        var ring = newRing();
        write(ring, "item", "value");
        var untrusted = new JsonSecretsFileReadOnlyCacheImpl(filePath(), KeyFileTrust.ADMINISTRATORS_ONLY, ring, new DefaultFormatProviderImpl());

        var e = assertThrows(UncheckedIOException.class, () -> untrusted.decrypt("item", new byte[16]));
        assertInstanceOf(AccessDeniedException.class, e.getCause());
        var async = assertFailsWith(UncheckedIOException.class, untrusted.decryptAsync("item", new byte[16]));
        assertInstanceOf(AccessDeniedException.class, async.getCause());
        assertEquals("value", decryptString(createCache(ring), "item"));
    }

    @Test
    void aFileOverTheMaximumLength_IsRefused() throws IOException {
        var ring = newRing();
        write(ring, "item", "value");
        var cache = createCache(ring, 16, null);

        var e = assertThrows(InvalidSecretDataException.class, () -> cache.decrypt("item", new byte[16]));
        assertTrue(e.getMessage().contains("larger than 16 bytes"), e.getMessage());
        assertFailsWith(InvalidSecretDataException.class, cache.findMaxDecryptedLengthAsync("item"));
    }

    @Test
    void aLargeValue_DecryptsAsCharacters() throws IOException {
        // Over the default format's limit, so ring and cache both allow longer values.
        var format = new DefaultFormatProviderImpl(16 * 1024);
        var ring = newRing(format, random(32));
        var value = "x".repeat(10_000);
        write(ring, "large", value);
        var cache = new JsonSecretsFileReadOnlyCacheImpl(filePath(), dir.trust(), ring, format);

        var result = new char[value.length()];
        assertEquals(value.length(), cache.decrypt("large", result));
        assertEquals(value, new String(result));
    }

    @Test
    void asyncLookups_FailInTheFuture_NeverThrow() throws IOException {
        // Java's counterpart of .NET's cancelled-token test: the file is read on the calling
        // thread, so there is nothing to cancel, but a failure still arrives through the future.
        var ring = newRing();
        write(ring, "item", "value");
        var cache = createCache(ring);

        assertFailsWith(NullPointerException.class, cache.decryptAsync(null, new byte[16]));
        assertFailsWith(NullPointerException.class, cache.decryptAsync(null, new char[16]));
        assertFailsWith(NullPointerException.class, cache.findMaxDecryptedLengthAsync(null));
    }

    @Test
    void sensitiveLogging_DoesntChangeTheResult() throws IOException {
        var ring = newRing();
        write(ring, "item", "value");
        var original = HkdfGuardTelemetry.CACHE.isSensitiveLoggingEnabled();
        HkdfGuardTelemetry.CACHE.setSensitiveLoggingEnabled(true);
        try {
            assertEquals("value", decryptString(createCache(ring), "item"));
        } finally {
            HkdfGuardTelemetry.CACHE.setSensitiveLoggingEnabled(original);
        }
    }

    @Test
    void constructor_ValidatesItsArguments() throws IOException {
        var ring = newRing();
        var format = new DefaultFormatProviderImpl();
        var trust = dir.trust();
        write(ring, "item", "value");

        assertThrows(NullPointerException.class, () -> new JsonSecretsFileReadOnlyCacheImpl(null, trust, ring, format));
        assertThrows(IllegalArgumentException.class, () -> new JsonSecretsFileReadOnlyCacheImpl(Path.of(""), trust, ring, format));
        assertThrows(NullPointerException.class, () -> new JsonSecretsFileReadOnlyCacheImpl(filePath(), null, ring, format));
        assertThrows(NullPointerException.class, () -> new JsonSecretsFileReadOnlyCacheImpl(filePath(), trust, null, format));
        assertThrows(NullPointerException.class, () -> new JsonSecretsFileReadOnlyCacheImpl(filePath(), trust, ring, null));
        assertThrows(IllegalArgumentException.class, () -> new JsonSecretsFileReadOnlyCacheImpl(filePath(), trust, ring, format, 0, null));
        assertThrows(IllegalArgumentException.class, () -> new JsonSecretsFileReadOnlyCacheImpl(filePath(), trust, ring, format, Integer.MAX_VALUE, null));
        assertThrows(NoSuchFileException.class, () -> new JsonSecretsFileReadOnlyCacheImpl(dir.path().resolve("absent.json"), trust, ring, format));
        assertThrows(NoSuchFileException.class, () -> new JsonSecretsFileReadOnlyCacheImpl(dir.path(), trust, ring, format));
        assertEquals(filePath().toAbsolutePath().normalize(), new JsonSecretsFileReadOnlyCacheImpl(filePath(), trust, ring, format).getFilePath());
    }

    @Test
    void aNullName_Throws() throws IOException {
        var ring = newRing();
        write(ring, "item", "value");
        var cache = createCache(ring);

        assertThrows(NullPointerException.class, () -> cache.decrypt(null, new byte[16]));
        assertThrows(NullPointerException.class, () -> cache.decrypt(null, new char[16]));
        assertThrows(NullPointerException.class, () -> cache.findMaxDecryptedLength(null));
        assertFalse(cache.findMaxDecryptedLength("item").isEmpty());
    }

    /** A pipeline writer over values held in memory, so a test can read exactly what it writes. */
    static final class InMemoryWriter extends SecretPipelineWriterBase {
        private final Map<String, String> secrets;

        InMemoryWriter(PipelineDataProtector protector, Map<String, String> secrets) {
            super(protector, List.copyOf(secrets.keySet()), name -> true);
            this.secrets = secrets;
        }

        @Override
        protected void readSecret(String name, List<SecretRequest> requests, Map<String, String> values) {
            var value = secrets.get(name).getBytes(StandardCharsets.UTF_8);
            protectSecret(value, value.length, requests, values);
        }
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
