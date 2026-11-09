package io.github.runsecure.hkdfguard.pipeline.contract;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import io.github.runsecure.hkdfguard.abstractions.SecretPipelineWriter;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmPipelineDataProtectorImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * What every {@link SecretPipelineWriter} must do, whatever its store: run against each store's
 * writer and fake by a test class extending this one, so every writer meets every scenario. Secret
 * names here are lower-case letters, digits and hyphens, which every store accepts; a store's own
 * tests cover what only it does.
 * <p>
 * Kept in hkdfguard-pipeline's src/contract-test/java and compiled into the tests of that module and
 * of each store's writer: one copy of the source, never shipped.
 */
public abstract class SecretPipelineWriterContractTest {
    /** The only key in the pipeline: no key ring anywhere. */
    protected AesGcmPipelineDataProtectorImpl protector;

    /** A folder to write to, which doesn't exist until a test makes it. */
    protected Path folder;

    @TempDir
    Path temp;

    @BeforeEach
    void createProtector() {
        protector = new AesGcmPipelineDataProtectorImpl(new DefaultFormatProviderImpl(), 3);
        folder = temp.resolve("hkdfguard-pipeline");
    }

    @AfterEach
    void closeProtector() {
        protector.close();
    }

    /** The store's writer, reading from this test's fake. */
    protected abstract SecretPipelineWriter createWriter(PipelineDataProtector protector, List<String> secretNames);

    /** Stores text as the value a name without a key reads. */
    protected abstract void setText(String name, String text);

    /** Stores a secret whose keys are the members of json, a JSON object - which may hold a member twice. */
    protected abstract void setKeys(String name, String json);

    /** Makes every later read fail as the store fails, with {@link #readFailure()}. */
    protected abstract void failReads();

    /** The exception a failing read fails with. */
    protected abstract Class<? extends Throwable> readFailure();

    /** The name of every secret the store was asked for, in order. */
    protected abstract List<String> reads();

    protected SecretPipelineWriter createWriter(String... secretNames) {
        return createWriter(protector, List.of(secretNames));
    }

    protected String decrypt(String encrypted, String fileName) {
        var result = new char[protector.getMaxDecryptedLength(encrypted)];
        return new String(result, 0, protector.decrypt(encrypted, fileName, result));
    }

    /** Pulls, waiting for the pull to complete; a failure is thrown as it is. */
    protected static void pull(SecretPipelineWriter writer) {
        try {
            writer.pullSecretsAsync().get(30, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof RuntimeException runtime)
                throw runtime;
            if (e.getCause() instanceof Error error)
                throw error;
            throw new AssertionError(e.getCause());
        } catch (InterruptedException | TimeoutException e) {
            throw new AssertionError("The pull did not complete.", e);
        }
    }

    /** Asserts a pull fails with {@code type}, and returns that failure. */
    protected static <E extends Throwable> E assertPullFails(Class<E> type, SecretPipelineWriter writer) {
        CompletableFuture<Void> pull = writer.pullSecretsAsync();
        try {
            pull.get(30, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            return assertInstanceOf(type, e.getCause());
        } catch (InterruptedException | TimeoutException e) {
            throw new AssertionError("The pull did not complete.", e);
        }
        return fail("Expected the pull to fail with " + type.getSimpleName() + ".");
    }

    /** Waits for a write to a stream to complete; a failure is thrown as it is. */
    protected static void await(CompletableFuture<Void> write) {
        try {
            write.get(30, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            if (e.getCause() instanceof RuntimeException runtime)
                throw runtime;
            throw new AssertionError(e.getCause());
        } catch (InterruptedException | TimeoutException e) {
            throw new AssertionError("The write did not complete.", e);
        }
    }

    private static final Pattern MEMBER = Pattern.compile("\"([^\"]*)\": \"([^\"]*)\"");

    /** The members of the JSON object of secrets, in order: names and values, neither escaped. */
    protected static Map<String, String> members(byte[] json) {
        var members = new LinkedHashMap<String, String>();
        var matcher = MEMBER.matcher(new String(json, StandardCharsets.UTF_8));
        while (matcher.find())
            members.put(matcher.group(1), matcher.group(2));
        return members;
    }

    /** The JSON object .NET's SecretPipelineWriter writes for these secrets, in their order, on this platform. */
    protected static byte[] expectedJson(Map<String, String> secrets) {
        var newLine = System.lineSeparator();
        var lines = new ArrayList<String>();
        for (var secret : secrets.entrySet())
            lines.add("  \"" + secret.getKey() + "\": \"" + secret.getValue() + "\"");
        return ("{" + newLine + String.join("," + newLine, lines) + newLine + "}").getBytes(StandardCharsets.UTF_8);
    }

    /** A process's standard input, as a test sees it: what was written, and whether it was flushed or closed. */
    protected static class RecordingStream extends ByteArrayOutputStream {
        public RecordingStream() {
        }

        public volatile boolean flushed;
        public volatile boolean closed;

        @Override
        public void flush() {
            flushed = true;
        }

        @Override
        public void close() {
            closed = true;
        }
    }

    protected List<String> filesInFolder() throws IOException {
        try (Stream<Path> files = Files.list(folder)) {
            return files.map(f -> f.getFileName().toString()).sorted().toList();
        }
    }

    @Test
    void pull_ReadsEachSecretOnce_AndKeepsEveryValueEncryptedForItsFileName() {
        setKeys("db-login", "{\"username\":\"app\",\"password\":\"s3cr\\\"et\",\"port\":5432,\"tls\":true,\"off\":false,\"unasked\":\"x\"}");
        setText("api-key", "api-key-value");
        try (var writer = createWriter("db-login#username", "db-login#password", "db-login#port", "db-login#tls", "db-login#off", "api-key")) {
            pull(writer);

            var secrets = writer.getProtectedSecrets();
            assertEquals(6, secrets.size());
            assertTrue(secrets.get("db-login__password").startsWith("enc::v3::"));
            assertEquals("app", decrypt(secrets.get("db-login__username"), "db-login__username"));
            assertEquals("s3cr\"et", decrypt(secrets.get("db-login__password"), "db-login__password"));
            assertEquals("5432", decrypt(secrets.get("db-login__port"), "db-login__port"));
            assertEquals("true", decrypt(secrets.get("db-login__tls"), "db-login__tls"));
            assertEquals("false", decrypt(secrets.get("db-login__off"), "db-login__off"));
            assertEquals("api-key-value", decrypt(secrets.get("api-key"), "api-key"));
            assertEquals(List.of("db-login", "api-key"), reads());
        }
    }

    @Test
    void aValue_IsBoundToItsFileName() {
        setText("item", "s3cret");
        try (var writer = createWriter("item")) {
            pull(writer);

            var encrypted = writer.getProtectedSecrets().get("item");
            assertThrows(CryptographicException.class, () -> decrypt(encrypted, "other"));
        }
    }

    @Test
    void aLargeValue_IsProtected() {
        // .NET's ArrayUtility.MaxStackChars + 1, the size past which it stops decoding on the stack.
        var large = "x".repeat(2_049);
        setText("big", large);
        try (var writer = createWriter("big")) {
            pull(writer);

            assertEquals(large, decrypt(writer.getProtectedSecrets().get("big"), "big"));
        }
    }

    @Test
    void aPullAgain_ReplacesWhatTheLastKept() {
        setText("item", "first");
        try (var writer = createWriter("item")) {
            pull(writer);
            setText("item", "second");

            pull(writer);

            assertEquals("second", decrypt(writer.getProtectedSecrets().get("item"), "item"));
        }
    }

    @Test
    void missingValues_AreAllReported_AndTheRestKept() throws IOException {
        setKeys("db-login", "{\"username\":\"app\",\"empty\":\"\",\"nothing\":null,\"nested\":{\"a\":\"b\"},\"list\":[1]}");
        setText("plain", "not json");
        setText("trailing", "{\"key\":\"v\"} more");
        setText("array", "[\"key\"]");
        setText("blank", "");
        try (var writer = createWriter("absent", "db-login#username", "db-login#password", "db-login#empty", "db-login#nothing",
                "db-login#nested", "db-login#list", "plain#key", "trailing#key", "array#key", "blank")) {
            var e = assertPullFails(NoSuchElementException.class, writer);

            assertEquals("The secret store holds no value for: absent, db-login#password, db-login#empty, db-login#nothing, "
                    + "db-login#nested, db-login#list, plain#key, trailing#key, array#key, blank.", e.getMessage());
            assertEquals(List.of("db-login__username"), List.copyOf(writer.getProtectedSecrets().keySet()));

            // What was found is still written.
            writer.writeProtectedSecretFiles(folder);
            assertEquals(List.of("db-login__username"), filesInFolder());
        }
    }

    @Test
    void aSecretHoldingAKeyTwice_IsRefused() {
        setKeys("db-login", "{\"password\":\"a\",\"password\":\"b\"}");
        try (var writer = createWriter("db-login#password")) {
            assertPullFails(InvalidSecretDataException.class, writer);
            assertTrue(writer.getProtectedSecrets().isEmpty());
        }
    }

    @Test
    void aFailedRead_Propagates_AndKeepsNothing() {
        setText("item", "s3cret");
        try (var writer = createWriter("item")) {
            pull(writer);
            failReads();

            assertPullFails(readFailure(), writer);

            assertTrue(writer.getProtectedSecrets().isEmpty());
            assertThrows(IllegalStateException.class, () -> writer.writeProtectedSecretFiles(folder));
        }
    }

    @Test
    void throughTheInterface_WritesOneFilePerSecret_AsUtf8WithoutABom() throws IOException {
        setKeys("db-login", "{\"password\":\"pässwörd\"}");
        setText("api-key", "key");
        try (SecretPipelineWriter writer = createWriter("db-login#password", "api-key")) {
            pull(writer);

            writer.writeProtectedSecretFiles(folder);

            assertEquals(List.of("api-key", "db-login__password"), filesInFolder());
            var bytes = Files.readAllBytes(folder.resolve("db-login__password"));
            assertNotEquals((byte) 0xEF, bytes[0]);
            assertEquals("pässwörd", decrypt(new String(bytes, StandardCharsets.UTF_8), "db-login__password"));
        }
    }

    @Test
    void throughTheInterface_WritesOneJsonObject_OfFileNamesAndValues() throws IOException {
        setKeys("db-login", "{\"password\":\"pässwörd\"}");
        setText("api-key", "key");
        try (SecretPipelineWriter writer = createWriter("db-login#password", "api-key")) {
            pull(writer);
            var path = folder.resolve("nested").resolve("secrets.json");

            writer.writeJsonSecrets(path);

            var bytes = Files.readAllBytes(path);
            assertEquals((byte) '{', bytes[0]);
            var secrets = writer.getProtectedSecrets();
            var members = members(bytes);
            assertEquals(List.of("api-key", "db-login__password"), List.copyOf(members.keySet()));
            assertEquals(secrets.get("db-login__password"), members.get("db-login__password"));
            assertEquals("pässwörd", decrypt(members.get("db-login__password"), "db-login__password"));
            // Byte for byte .NET's layout: indented, relaxed escaping ('+' kept as it is), no BOM.
            var expected = new LinkedHashMap<String, String>();
            expected.put("api-key", secrets.get("api-key"));
            expected.put("db-login__password", secrets.get("db-login__password"));
            assertArrayEquals(expectedJson(expected), bytes);
            assertFalse(new String(bytes, StandardCharsets.UTF_8).contains("\\u"));
        }
    }

    @Test
    void writeJsonSecrets_ReplacesTheFile_AndNeedsAPullAndAPath() throws IOException {
        try (var writer = createWriter("item")) {
            var path = folder.resolve("secrets.json");
            assertThrows(IllegalStateException.class, () -> writer.writeJsonSecrets(path));
            assertThrows(NullPointerException.class, () -> writer.writeJsonSecrets(null));
            assertThrows(IllegalArgumentException.class, () -> writer.writeJsonSecrets(Path.of("")));
            assertFalse(Files.exists(folder));

            Files.createDirectories(folder);
            Files.writeString(path, "{\"stale\":\"value\",\"padding\":\"making the old file longer than the new one\"}");
            setText("item", "new");
            pull(writer);

            writer.writeJsonSecrets(path);

            var members = members(Files.readAllBytes(path));
            assertEquals(List.of("item"), List.copyOf(members.keySet()));
            assertEquals("new", decrypt(members.get("item"), "item"));
        }
    }

    @Test
    void throughTheInterface_StreamsATarOfTheFiles_ThatAnyTarUnpacks() throws IOException {
        setKeys("db-login", "{\"password\":\"pässwörd\"}");
        setText("api-key", "key");
        try (SecretPipelineWriter writer = createWriter("db-login#password", "api-key")) {
            pull(writer);
            var stdin = new RecordingStream();
            var before = Instant.now().getEpochSecond();

            await(writer.writeProtectedSecretFilesAsync(stdin));

            assertTrue(stdin.flushed);
            assertFalse(stdin.closed);
            var entries = TarEntries.read(stdin.toByteArray());
            assertEquals(List.of("api-key", "db-login__password"), entries.stream().map(TarEntries.Entry::name).toList());
            for (var entry : entries) {
                assertEquals('0', entry.type());
                assertEquals(0644, entry.mode());
                assertTrue(entry.mtime() >= before && entry.mtime() <= Instant.now().getEpochSecond(), String.valueOf(entry.mtime()));
            }
            assertEquals(writer.getProtectedSecrets().get("db-login__password"), entries.get(1).text());
            assertEquals("pässwörd", decrypt(entries.get(1).text(), "db-login__password"));

            // The same files writeProtectedSecretFiles writes, byte for byte.
            writer.writeProtectedSecretFiles(folder);
            for (var entry : entries)
                assertArrayEquals(Files.readAllBytes(folder.resolve(entry.name())), entry.data());
        }
    }

    @Test
    void throughTheInterface_StreamsTheJsonObject_AsTheFileHoldsIt() throws IOException {
        setText("item", "s3cret");
        try (SecretPipelineWriter writer = createWriter("item")) {
            pull(writer);
            var stdin = new RecordingStream();

            await(writer.writeJsonSecretsAsync(stdin));
            writer.writeJsonSecrets(folder.resolve("secrets.json"));

            assertTrue(stdin.flushed);
            assertFalse(stdin.closed);
            assertArrayEquals(Files.readAllBytes(folder.resolve("secrets.json")), stdin.toByteArray());
            assertEquals("s3cret", decrypt(members(stdin.toByteArray()).get("item"), "item"));
        }
    }

    @Test
    void theStreamWrites_NeedAPullAndAStream() {
        try (var writer = createWriter("item")) {
            var stdin = new ByteArrayOutputStream();

            assertThrows(IllegalStateException.class, () -> writer.writeProtectedSecretFilesAsync(stdin));
            assertThrows(IllegalStateException.class, () -> writer.writeJsonSecretsAsync(stdin));
            assertThrows(NullPointerException.class, () -> writer.writeProtectedSecretFilesAsync(null));
            assertThrows(NullPointerException.class, () -> writer.writeJsonSecretsAsync(null));
            assertEquals(0, stdin.size());
        }
    }

    @Test
    void writeProtectedSecretFiles_ReplacesOnlyItsOwnFiles() throws IOException {
        Files.createDirectories(folder);
        Files.writeString(folder.resolve("item"), "old");
        Files.writeString(folder.resolve("unrelated"), "untouched");
        setText("item", "new");
        try (var writer = createWriter("item")) {
            pull(writer);

            writer.writeProtectedSecretFiles(folder);

            assertEquals("new", decrypt(Files.readString(folder.resolve("item")), "item"));
            assertEquals("untouched", Files.readString(folder.resolve("unrelated")));
        }
    }

    @Test
    void writeProtectedSecretFiles_BeforeAPull_OrWithoutAFolder_Throws() {
        try (var writer = createWriter("item")) {
            assertThrows(IllegalStateException.class, () -> writer.writeProtectedSecretFiles(folder));
            assertThrows(NullPointerException.class, () -> writer.writeProtectedSecretFiles(null));
            assertThrows(IllegalArgumentException.class, () -> writer.writeProtectedSecretFiles(Path.of("")));
            assertFalse(Files.exists(folder));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "bad name", "#key", "db-login#", "db-login#bad key", "db-login#a:b"})
    void anInvalidName_IsRefused(String secretName) {
        assertThrows(IllegalArgumentException.class, () -> createWriter(secretName));
    }

    @Test
    void constructor_ChecksTheListAndTheProtector() {
        assertThrows(NullPointerException.class, () -> createWriter(null, List.of("item")));
        assertThrows(NullPointerException.class, () -> createWriter(protector, null));
        assertThrows(IllegalArgumentException.class, () -> createWriter(protector, List.of()));
        assertThrows(IllegalArgumentException.class, () -> createWriter(protector, Arrays.asList((String) null)));
        assertThrows(IllegalArgumentException.class, () -> createWriter(protector, List.of("item", "ITEM")));
        assertThrows(IllegalArgumentException.class, () -> createWriter(protector, List.of("item", "item")));
    }
}
