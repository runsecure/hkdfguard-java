package io.github.runsecure.hkdfguard.pipeline;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import io.github.runsecure.hkdfguard.abstractions.SecretPipelineWriter;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.pipeline.contract.SecretPipelineWriterContractTest;
import io.github.runsecure.hkdfguard.pipeline.contract.TarEntries;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** The shared writer's contract over an in-memory store, and what only it does: the default key, file names, its own arguments. */
class SecretPipelineWriterBaseTest extends SecretPipelineWriterContractTest {
    private final FakeStore store = new FakeStore();

    @Override
    protected SecretPipelineWriter createWriter(PipelineDataProtector protector, List<String> secretNames) {
        return new FakeWriter(protector, secretNames, store);
    }

    @Override
    protected void setText(String name, String text) {
        store.set(name, text);
    }

    @Override
    protected void setKeys(String name, String json) {
        store.set(name, json);
    }

    @Override
    protected void failReads() {
        store.failWith = new UncheckedIOException(new IOException("down"));
    }

    @Override
    protected Class<? extends Throwable> readFailure() {
        return UncheckedIOException.class;
    }

    @Override
    protected List<String> reads() {
        return store.reads;
    }

    @Test
    void aNameWithoutAKey_ReadsTheWholeValue_OrTheDefaultKeyWhenThereIsOne() {
        store.set("app", "{\"value\":\"s3cret\"}");
        try (var whole = new FakeWriter(protector, List.of("app"), store);
                var byDefault = new FakeWriter(protector, List.of("app"), store, "value")) {
            pull(whole);
            pull(byDefault);

            assertEquals("{\"value\":\"s3cret\"}", decrypt(whole.getProtectedSecrets().get("app"), "app"));
            assertEquals("s3cret", decrypt(byDefault.getProtectedSecrets().get("app"), "app"));
        }
    }

    @Test
    void aSecretIsReadOnce_ForItsWholeValueAndItsKeys() {
        store.set("prod/app", "{\"user\":\"app\"}");
        try (var writer = new FakeWriter(protector, List.of("prod/app", "prod/app#user"), store)) {
            pull(writer);

            assertEquals(List.of("prod/app"), store.reads);
            assertEquals("{\"user\":\"app\"}", decrypt(writer.getProtectedSecrets().get("prod__app"), "prod__app"));
            assertEquals("app", decrypt(writer.getProtectedSecrets().get("prod__app__user"), "prod__app__user"));
        }
    }

    @Test
    void theProtectedSecrets_MatchFileNamesIgnoringCase_AndCantBeChanged() {
        store.set("App", "s3cret");
        try (var writer = new FakeWriter(protector, List.of("App"), store)) {
            pull(writer);

            assertEquals(writer.getProtectedSecrets().get("App"), writer.getProtectedSecrets().get("APP"));
            assertThrows(UnsupportedOperationException.class, () -> writer.getProtectedSecrets().clear());
        }
    }

    @Test
    void aValueThatIsntUtf8Text_IsRefused() {
        store.secrets.put("binary", new byte[] {(byte) 0xFF, (byte) 0xFE, 0x00, (byte) 0x80});
        try (var writer = new FakeWriter(protector, List.of("binary"), store)) {
            assertPullFails(InvalidSecretDataException.class, writer);
            assertTrue(writer.getProtectedSecrets().isEmpty());
        }
    }

    @Test
    void aWhitespaceValue_HoldsNoKeys() {
        store.set("blank", "   ");
        try (var writer = new FakeWriter(protector, List.of("blank#key"), store)) {
            assertPullFails(NoSuchElementException.class, writer);
        }
    }

    @Test
    void throughTheInterface_ClosingClosesTheStore() {
        var writer = new FakeWriter(protector, List.of("app"), store);

        ((SecretPipelineWriter) writer).close();

        assertTrue(writer.closed);
    }

    @Test
    void cancellingAPull_CancelsTheReadInProgress_AndKeepsNothing() throws InterruptedException {
        var started = new CountDownLatch(1);
        var interrupted = new CountDownLatch(1);
        try (var writer = new SecretPipelineWriterBase(protector, List.of("item"), FakeStore::isValidName) {
            @Override
            protected void readSecret(String name, List<SecretRequest> requests, Map<String, String> values) {
                started.countDown();
                try {
                    Thread.sleep(30_000);
                } catch (InterruptedException e) {
                    interrupted.countDown();
                    throw new CancellationException("interrupted");
                }
            }
        }) {
            var pull = writer.pullSecretsAsync();
            assertTrue(started.await(10, TimeUnit.SECONDS));

            pull.cancel(true);

            assertTrue(interrupted.await(10, TimeUnit.SECONDS));
            assertTrue(writer.getProtectedSecrets().isEmpty());
            assertThrows(IllegalStateException.class, () -> writer.writeProtectedSecretFiles(folder));
        }
    }

    @Test
    void anAsynchronousStore_IsReadOneSecretAfterAnother() {
        var order = new ArrayList<String>();
        try (var writer = new SecretPipelineWriterBase(protector, List.of("a", "b", "c"), FakeStore::isValidName) {
            @Override
            protected void readSecret(String name, List<SecretRequest> requests, Map<String, String> values) {
                throw new AssertionError("readSecretAsync is overridden.");
            }

            @Override
            protected CompletableFuture<Void> readSecretAsync(String name, List<SecretRequest> requests, Map<String, String> values) {
                return CompletableFuture.runAsync(() -> {
                    synchronized (order) {
                        order.add(name);
                    }
                    var value = name.getBytes(StandardCharsets.UTF_8);
                    protectSecret(value, value.length, requests, values);
                });
            }
        }) {
            pull(writer);

            synchronized (order) {
                assertEquals(List.of("a", "b", "c"), order);
            }
            assertEquals("b", decrypt(writer.getProtectedSecrets().get("b"), "b"));
        }
    }

    @Test
    void theStreamsAndTheJsonFile_AreInOrdinalFileNameOrder_AndALongNameIsWholeInTheArchive() throws Exception {
        var longName = "n".repeat(120);
        for (var name : List.of("alpha", longName, "Zeta", "beta"))
            store.set(name, "value of " + name);
        try (var writer = new FakeWriter(protector, List.of("alpha", longName, "Zeta", "beta"), store)) {
            pull(writer);
            var tar = new RecordingStream();
            var json = new RecordingStream();

            await(writer.writeProtectedSecretFilesAsync(tar));
            await(writer.writeJsonSecretsAsync(json));

            var order = List.of("Zeta", "alpha", "beta", longName);
            var entries = TarEntries.read(tar.toByteArray());
            assertEquals(order, entries.stream().map(TarEntries.Entry::name).toList());
            assertEquals(longName, entries.get(3).extended().get("path"));
            assertEquals("value of " + longName, decrypt(entries.get(3).text(), longName));
            assertEquals(order, List.copyOf(members(json.toByteArray()).keySet()));
        }
    }

    @Test
    void aPullThatFoundNothing_WritesAnEmptyObject_AndAnEmptyArchive() throws IOException {
        try (var writer = new FakeWriter(protector, List.of("absent"), store)) {
            assertPullFails(NoSuchElementException.class, writer);
            var tar = new RecordingStream();
            var json = new RecordingStream();

            await(writer.writeProtectedSecretFilesAsync(tar));
            await(writer.writeJsonSecretsAsync(json));
            writer.writeJsonSecrets(folder.resolve("secrets.json"));

            assertArrayEquals(new byte[1024], tar.toByteArray());
            assertEquals("{}", json.toString(StandardCharsets.UTF_8));
            assertEquals("{}", Files.readString(folder.resolve("secrets.json")));
        }
    }

    // --- Writing files: never through what is already there ------------------------------------

    /** Writes a file outside the output folder that a link planted in it will point to. */
    private java.nio.file.Path victim() throws IOException {
        var victim = folder.resolveSibling("victim.txt");
        Files.writeString(victim, "do not overwrite");
        return victim;
    }

    /** {@code link}, a symbolic link to {@code target}; the test is skipped where this account can't make one (Windows without the privilege). */
    private static void symbolicLink(java.nio.file.Path link, java.nio.file.Path target) {
        try {
            Files.createSymbolicLink(link, target);
        } catch (IOException | UnsupportedOperationException e) {
            org.junit.jupiter.api.Assumptions.abort("Symbolic links can't be made here: " + e);
        }
    }

    private void writeItem(java.util.function.Consumer<FakeWriter> write) {
        store.set("item", "s3cret");
        try (var writer = new FakeWriter(protector, List.of("item"), store)) {
            pull(writer);
            write.accept(writer);
        }
    }

    private static void writeFiles(FakeWriter writer, java.nio.file.Path folder) {
        try {
            writer.writeProtectedSecretFiles(folder);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static void writeJson(FakeWriter writer, java.nio.file.Path path) {
        try {
            writer.writeJsonSecrets(path);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Test
    void aSymbolicLinkPlantedUnderASecretsName_IsReplaced_NotWrittenThrough() throws IOException {
        var victim = victim();
        Files.createDirectories(folder);
        symbolicLink(folder.resolve("item"), victim);

        writeItem(writer -> writeFiles(writer, folder));

        assertEquals("do not overwrite", Files.readString(victim));
        assertTrue(Files.isRegularFile(folder.resolve("item"), java.nio.file.LinkOption.NOFOLLOW_LINKS));
        assertEquals("s3cret", decrypt(Files.readString(folder.resolve("item")), "item"));
        assertEquals(List.of("item"), filesInFolder());
    }

    @Test
    void aHardLinkPlantedUnderASecretsName_IsReplaced_NotWrittenThrough() throws IOException {
        var victim = victim();
        Files.createDirectories(folder);
        Files.createLink(folder.resolve("item"), victim);

        writeItem(writer -> writeFiles(writer, folder));

        assertEquals("do not overwrite", Files.readString(victim));
        assertEquals("s3cret", decrypt(Files.readString(folder.resolve("item")), "item"));
    }

    @Test
    void aLinkPlantedAtTheJsonFilesPath_IsReplaced_NotWrittenThrough() throws IOException {
        var victim = victim();
        Files.createDirectories(folder);
        var path = folder.resolve("secrets.json");
        Files.createLink(path, victim);

        writeItem(writer -> writeJson(writer, path));

        assertEquals("do not overwrite", Files.readString(victim));
        assertEquals("s3cret", decrypt(members(Files.readAllBytes(path)).get("item"), "item"));
        assertEquals(List.of("secrets.json"), filesInFolder());
    }

    @Test
    void aWriteThatCanNotBeRenamedIntoPlace_LeavesNothingBehind() throws IOException {
        // A folder by the secret's name, not empty: nothing can replace it.
        Files.createDirectories(folder.resolve("item"));
        Files.writeString(folder.resolve("item").resolve("keep"), "kept");

        store.set("item", "s3cret");
        try (var writer = new FakeWriter(protector, List.of("item"), store)) {
            pull(writer);
            assertThrows(IOException.class, () -> writer.writeProtectedSecretFiles(folder));
        }

        assertEquals("kept", Files.readString(folder.resolve("item").resolve("keep")));
        try (var entries = Files.list(folder)) {
            assertEquals(List.of("item"), entries.map(entry -> entry.getFileName().toString()).toList());
        }
    }

    @Test
    @org.junit.jupiter.api.condition.DisabledOnOs(org.junit.jupiter.api.condition.OS.WINDOWS)
    void aReplacedFile_KeepsItsPosixPermissions() throws IOException {
        Files.createDirectories(folder);
        var path = folder.resolve("item");
        Files.writeString(path, "old");
        var permissions = java.nio.file.attribute.PosixFilePermissions.fromString("rw-r-----");
        Files.setPosixFilePermissions(path, permissions);

        writeItem(writer -> writeFiles(writer, folder));

        assertEquals(permissions, Files.getPosixFilePermissions(path));
        assertEquals("s3cret", decrypt(Files.readString(path), "item"));
    }

    @Test
    void aStreamThatFails_FailsTheWrite() {
        store.set("item", "s3cret");
        try (var writer = new FakeWriter(protector, List.of("item"), store)) {
            pull(writer);
            var broken = new RecordingStream() {
                @Override
                public void flush() {
                    throw new UncheckedIOException(new IOException("Broken pipe"));
                }

                @Override
                public synchronized void write(byte[] b, int off, int len) {
                    throw new UncheckedIOException(new IOException("Broken pipe"));
                }
            };
            var closing = new OutputStream() {
                @Override
                public void write(int b) throws IOException {
                    throw new IOException("Broken pipe");
                }
            };

            assertInstanceOf(UncheckedIOException.class, failure(writer.writeJsonSecretsAsync(broken)));
            assertInstanceOf(IOException.class, failure(writer.writeProtectedSecretFilesAsync(closing)));
            assertInstanceOf(IOException.class, failure(writer.writeJsonSecretsAsync(closing)));
        }
    }

    @Test
    void aStreamWrite_TakesWhatWasHeldWhenCalled_AndCancellingItInterruptsIt() throws Exception {
        store.set("item", "first");
        try (var writer = new FakeWriter(protector, List.of("item"), store)) {
            pull(writer);
            var writing = new CountDownLatch(1);
            var release = new CountDownLatch(1);
            var interrupted = new CountDownLatch(1);
            var blocking = new RecordingStream() {
                @Override
                public synchronized void write(byte[] b, int off, int len) {
                    writing.countDown();
                    try {
                        if (!release.await(30, TimeUnit.SECONDS))
                            throw new AssertionError("Never released.");
                    } catch (InterruptedException e) {
                        interrupted.countDown();
                        throw new UncheckedIOException(new InterruptedIOException("interrupted"));
                    }
                    super.write(b, off, len);
                }
            };

            var write = writer.writeJsonSecretsAsync(blocking);
            assertTrue(writing.await(10, TimeUnit.SECONDS));
            store.set("item", "second");
            pull(writer);
            release.countDown();
            await(write);
            assertEquals("first", decrypt(members(blocking.toByteArray()).get("item"), "item"));

            var stuck = new RecordingStream() {
                @Override
                public synchronized void write(byte[] b, int off, int len) {
                    try {
                        new CountDownLatch(1).await(30, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        interrupted.countDown();
                        throw new UncheckedIOException(new InterruptedIOException("interrupted"));
                    }
                }
            };
            var cancelled = writer.writeProtectedSecretFilesAsync(stuck);
            cancelled.cancel(true);
            assertTrue(cancelled.isCancelled());
            // Interrupted, unless it was cancelled before its thread wrote anything.
            interrupted.await(1, TimeUnit.SECONDS);
            assertEquals(0, stuck.size());
        }
    }

    private static Throwable failure(CompletableFuture<Void> write) {
        try {
            write.get(10, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            return e.getCause();
        } catch (InterruptedException | TimeoutException e) {
            throw new AssertionError("The write did not complete.", e);
        }
        throw new AssertionError("The write succeeded.");
    }

    @ParameterizedTest
    @CsvSource({"prod/app#password, prod__app__password", "prod/app, prod__app", "app, app"})
    void getFileName_ReplacesEachSeparator(String secretName, String fileName) {
        assertEquals(fileName, SecretPipelineWriterBase.getFileName(secretName));
    }

    @Test
    void namesMappingToOneFileName_AreRefused() {
        assertThrows(IllegalArgumentException.class, () -> new FakeWriter(protector, List.of("a/b", "a#b"), store));
    }

    @Test
    void constructor_ChecksTheDefaultKeyAndTheNameRule() {
        assertThrows(NullPointerException.class, () -> SecretPipelineWriterBase.getFileName(null));
        assertThrows(IllegalArgumentException.class, () -> new FakeWriter(protector, List.of("app"), store, ""));
        assertThrows(IllegalArgumentException.class, () -> new FakeWriter(protector, List.of("app"), store, "a#b"));
        assertThrows(NullPointerException.class, () -> new SecretPipelineWriterBase(protector, List.of("app"), null) {
            @Override
            protected void readSecret(String name, List<SecretRequest> requests, Map<String, String> values) {
            }
        });
    }

    @ParameterizedTest
    @CsvSource({"616263, true", "c3a4, true", "e282ac, true", "f09f9880, true", "ff, false", "c0af, false", "e080af, false",
            "eda080, false", "f4908080, false", "c3, false", "e282, false", "80, false"})
    void isUtf8_IsDotNetsRule(String hex, boolean valid) {
        var bytes = HexFormat.of().parseHex(hex);
        assertEquals(valid, SecretPipelineWriterBase.isUtf8(bytes, 0, bytes.length));
    }
}
