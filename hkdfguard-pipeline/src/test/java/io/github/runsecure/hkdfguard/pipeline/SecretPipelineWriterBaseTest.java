package io.github.runsecure.hkdfguard.pipeline;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import io.github.runsecure.hkdfguard.abstractions.SecretPipelineWriter;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.pipeline.contract.SecretPipelineWriterContractTest;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
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
