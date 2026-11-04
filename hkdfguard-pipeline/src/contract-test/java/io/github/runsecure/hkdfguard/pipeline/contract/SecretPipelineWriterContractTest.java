package io.github.runsecure.hkdfguard.pipeline.contract;

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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
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

    private List<String> filesInFolder() throws IOException {
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
