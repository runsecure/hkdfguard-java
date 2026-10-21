package io.github.runsecure.hkdfguard.dataencryptionkey;

import static io.github.runsecure.hkdfguard.dataencryptionkey.Futures.await;
import static io.github.runsecure.hkdfguard.dataencryptionkey.Futures.awaitFailure;
import static io.github.runsecure.hkdfguard.dataencryptionkey.TestKeys.utf8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.CryptoProvider;
import io.github.runsecure.hkdfguard.abstractions.InvalidKeyFileException;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class KeyRingBuilderTest {
    @TempDir
    Path directory;

    private Path keyFile(String name, byte[] content) throws IOException {
        return Files.write(directory.resolve(name), content);
    }

    private static KeyRingBuilder configured(io.github.runsecure.hkdfguard.abstractions.CryptoProviderFactory factory) {
        return new KeyRingBuilder()
                .withKeyWrapper(new TestKeys.FakeKeyWrapper(TestKeys.randomKey()))
                .withCryptoProviderFactory(factory)
                .withKeyRefreshInterval(60);
    }

    private static void assertClosed(CryptoProvider provider) {
        assertThrows(IllegalStateException.class, () -> provider.encrypt(new byte[] {1}, new byte[64]));
    }

    // --- Configuration --------------------------------------------------------------------------

    @Test
    void withServiceName_SetsIt_AndRejectsAnInvalidOrNullName() {
        assertEquals("my.service", new KeyRingBuilder().withServiceName("my.service").getServiceName());

        for (var invalid : new String[] {".service", "my..service", "my-service", ""}) {
            var builder = new KeyRingBuilder();
            assertThrows(IllegalArgumentException.class, () -> builder.withServiceName(invalid));
            assertNull(builder.getServiceName());
        }
        assertThrows(NullPointerException.class, () -> new KeyRingBuilder().withServiceName(null));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 300})
    void withKeyRefreshInterval_WithinRange_SetsIt(int interval) {
        assertEquals(interval, new KeyRingBuilder().withKeyRefreshInterval(interval).getKeyRefreshInterval());
    }

    @ParameterizedTest
    @ValueSource(ints = {-1, 0, 301})
    void withKeyRefreshInterval_OutOfRange_Throws(int interval) {
        assertThrows(IllegalArgumentException.class, () -> new KeyRingBuilder().withKeyRefreshInterval(interval));
    }

    @Test
    void maxRefreshFailures_DefaultsToThree_CanBeSet_AndFailOpenClearsIt() {
        assertEquals(3, KeyRingBuilder.DEFAULT_MAX_REFRESH_FAILURES);
        var builder = new KeyRingBuilder();
        assertEquals(3, builder.getMaxRefreshFailures());

        builder.withMaxRefreshFailures(5);
        assertEquals(5, builder.getMaxRefreshFailures());
        assertSame(builder, builder.withFailOpenOnRefreshFailure());
        assertNull(builder.getMaxRefreshFailures());
        builder.withMaxRefreshFailures(2);
        assertEquals(2, builder.getMaxRefreshFailures());

        assertThrows(IllegalArgumentException.class, () -> new KeyRingBuilder().withMaxRefreshFailures(0));
    }

    @Test
    void withKeyFile_TheSameVersionTwice_Throws() {
        var builder = new KeyRingBuilder().withKeyFile(1, "a.bin");

        assertThrows(IllegalArgumentException.class, () -> builder.withKeyFile(1, "b.bin"));
    }

    @Test
    void buildAsync_WithMissingConfiguration_ThrowsNamingWhatIsMissing() {
        var factory = new AesGcmCryptoProviderFactoryImpl();
        var wrapper = new TestKeys.FakeKeyWrapper(TestKeys.randomKey());

        var noWrapper = assertThrows(IllegalStateException.class,
                () -> new KeyRingBuilder().withCryptoProviderFactory(factory).withKeyRefreshInterval(60).withEphemeralKey(1).buildAsync());
        assertEquals("A key wrapper is required - call withKeyWrapper first.", noWrapper.getMessage());

        var noFactory = assertThrows(IllegalStateException.class,
                () -> new KeyRingBuilder().withKeyWrapper(wrapper).withKeyRefreshInterval(60).withEphemeralKey(1).buildAsync());
        assertEquals("A crypto provider factory is required - call withCryptoProviderFactory first.", noFactory.getMessage());

        assertThrows(IllegalStateException.class, () -> configured(factory).buildAsync());
        assertThrows(IllegalStateException.class,
                () -> new KeyRingBuilder().withKeyWrapper(wrapper).withCryptoProviderFactory(factory).withEphemeralKey(1).buildAsync());
    }

    // --- Building -------------------------------------------------------------------------------

    @Test
    void build_FromKeyFilesAndEphemeralKeys_GivesAWorkingRingWhoseHighestVersionIsCurrent() throws IOException {
        var first = keyFile("v1.bin", utf8("wrapped-v1"));
        var second = keyFile("v2.bin", utf8("wrapped-v2"));

        try (var ring = await(configured(new AesGcmCryptoProviderFactoryImpl()).withKeyFile(1, first).withKeyFile(2, second).withEphemeralKey(3).buildAsync())) {
            assertEquals(3, ring.getCurrentVersion());
            var protector = ring.createProtector("purpose");
            var result = new char[16];
            assertEquals("hello", new String(result, 0, protector.decrypt(protector.encrypt("hello"), result)));

            var key = ring.get(1);
            var decrypted = new byte[10];
            assertArrayEquals(utf8("top secret"), Arrays.copyOf(decrypted, key.decrypt(key.encrypt(utf8("top secret")), decrypted)));
        }
    }

    @Test
    void build_UsesTheConfiguredFormatProvider() {
        var recording = new KeyRingImplTest.RecordingFormatProvider();

        try (var ring = await(configured(new AesGcmCryptoProviderFactoryImpl()).withEphemeralKey(1).withFormatProvider(recording).buildAsync())) {
            ring.createProtector("purpose").encrypt("hello");
            assertTrue(recording.formatCalled);
        }
    }

    @Test
    void build_PassesTheKeyRefreshInterval_NotTheVersion_ToBothFactoryPaths() throws IOException {
        // Regression: the ephemeral path once passed the ring version as the refresh interval.
        var factory = new TestKeys.RecordingCryptoProviderFactory();

        try (var ignored = await(new KeyRingBuilder().withKeyWrapper(new TestKeys.FakeKeyWrapper(TestKeys.randomKey()))
                .withCryptoProviderFactory(factory).withKeyRefreshInterval(123)
                .withKeyFile(1, keyFile("v1.bin", utf8("wrapped"))).withEphemeralKey(42).buildAsync())) {
            assertEquals(List.of(123), factory.createExpirySecondsCalls);
            assertEquals(List.of(123), factory.createEphemeralExpirySecondsCalls);
        }
    }

    @Test
    void build_PassesTheRefreshFailurePolicyToBothFactoryPaths() throws IOException {
        var path = keyFile("v1.bin", utf8("wrapped"));
        var withPolicy = new TestKeys.RecordingCryptoProviderFactory();
        var withDefault = new TestKeys.RecordingCryptoProviderFactory();
        var failOpen = new TestKeys.RecordingCryptoProviderFactory();

        try (var a = await(configured(withPolicy).withMaxRefreshFailures(5).withKeyFile(1, path).withEphemeralKey(2).buildAsync());
             var b = await(configured(withDefault).withKeyFile(1, path).withEphemeralKey(2).buildAsync());
             var c = await(configured(failOpen).withFailOpenOnRefreshFailure().withKeyFile(1, path).withEphemeralKey(2).buildAsync())) {
            assertEquals(List.of(5, 5), withPolicy.maxRefreshFailuresCalls);
            assertEquals(List.of(3, 3), withDefault.maxRefreshFailuresCalls);
            assertEquals(Arrays.asList(null, null), failOpen.maxRefreshFailuresCalls);
        }
    }

    @Test
    void build_WhenAVersionIsRegisteredTwice_ClosesEveryProviderItCreated() throws IOException {
        var factory = new TestKeys.RecordingCryptoProviderFactory();

        awaitFailure(IllegalArgumentException.class, configured(factory).withKeyFile(1, keyFile("v1.bin", utf8("wrapped"))).withEphemeralKey(1).buildAsync());

        assertEquals(2, factory.createdProviders.size());
        factory.createdProviders.forEach(KeyRingBuilderTest::assertClosed);
    }

    @Test
    void buildAsync_WithAKeyFileAboveEveryEphemeralVersion_AndRotationOn_ThrowsBeforeReadingAnyKeyFile() {
        // The first rotation would add an ephemeral key above the key file and make it current.
        var wrapper = new ReadingKeyWrapper();
        var factory = new TestKeys.RecordingCryptoProviderFactory();
        var builder = new KeyRingBuilder().withKeyWrapper(wrapper).withCryptoProviderFactory(factory).withKeyRefreshInterval(60)
                .withKeyFile(3, directory.resolve("v3.bin")).withEphemeralKey(2);

        var thrown = assertThrows(IllegalStateException.class, builder::buildAsync);

        assertTrue(thrown.getMessage().startsWith("Key file version 3 is above every ephemeral version"));
        assertTrue(wrapper.reads.isEmpty());
        assertTrue(factory.createdProviders.isEmpty());
    }

    @Test
    void build_WithAKeyFileAboveEveryEphemeralVersion_AndRotationOff_KeepsTheKeyFileCurrent() {
        var factory = new TestKeys.RecordingCryptoProviderFactory();

        try (var ring = await(new KeyRingBuilder().withKeyWrapper(new ReadingKeyWrapper()).withCryptoProviderFactory(factory)
                .withKeyRefreshInterval(60).withKeyFile(3, directory.resolve("v3.bin")).withEphemeralKey(2)
                .withoutEphemeralKeyRotation().buildAsync())) {
            assertEquals(3, ring.getCurrentVersion());
            assertNull(ring.getEphemeralKeyRotationInterval());
        }
    }

    @Test
    void build_WhenAKeyFileCannotBeRead_ClosesTheProvidersAlreadyCreated() throws IOException {
        var factory = new TestKeys.RecordingCryptoProviderFactory();

        awaitFailure(NoSuchFileException.class, configured(factory)
                .withKeyFile(1, keyFile("v1.bin", utf8("wrapped")))
                .withKeyFile(2, directory.resolve("missing.bin"))
                .buildAsync());

        assertEquals(1, factory.createdProviders.size());
        assertClosed(factory.createdProviders.getFirst());
    }

    @Test
    void theBuiltRing_OwnsItsProviders() {
        var factory = new TestKeys.RecordingCryptoProviderFactory();
        var ring = await(configured(factory).withEphemeralKey(1).buildAsync());

        ring.close();

        assertClosed(factory.createdProviders.getFirst());
    }

    // --- Key file limits ------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(ints = {1, 156, WrappedKeyLimits.MAX_BYTES})
    void keyFilesUpToTheLimit_AreReadWhole(int length) throws IOException {
        var content = new byte[length];
        new java.security.SecureRandom().nextBytes(content);
        var path = keyFile("v1.bin", content);
        var factory = new TestKeys.RecordingCryptoProviderFactory();

        try (var ignored = await(configured(factory).withKeyFile(1, path).buildAsync())) {
            assertEquals(1, factory.createdWrapped.size());
            assertArrayEquals(content, factory.createdWrapped.getFirst());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {WrappedKeyLimits.MAX_BYTES + 1, 10 * 1024 * 1024})
    void keyFilesOverTheLimit_AreRefused(int length) throws IOException {
        var path = keyFile("big.bin", new byte[length]);

        var ex = awaitFailure(InvalidKeyFileException.class, configured(new AesGcmCryptoProviderFactoryImpl()).withKeyFile(1, path).buildAsync());

        assertTrue(ex.getMessage().contains("larger than " + WrappedKeyLimits.MAX_BYTES + " bytes"));
    }

    @Test
    void anEmptyKeyFile_IsRefused() throws IOException {
        var path = keyFile("empty.bin", new byte[0]);

        var ex = awaitFailure(InvalidKeyFileException.class, configured(new AesGcmCryptoProviderFactoryImpl()).withKeyFile(1, path).buildAsync());

        assertTrue(ex.getMessage().contains("is empty"));
    }

    // --- Key files are read through the key wrapper ---------------------------------------------

    /** A wrapper that reads its own "key files" - none of which exist on disk. */
    private static final class ReadingKeyWrapper extends TestKeys.FakeKeyWrapper {
        final List<Path> reads = new CopyOnWriteArrayList<>();
        volatile IOException failure;
        volatile Path failingPath;

        ReadingKeyWrapper() {
            super(TestKeys.randomKey());
        }

        @Override
        public CompletableFuture<byte[]> readKeyFileAsync(Path path) {
            reads.add(path);
            if (failure != null && path.equals(failingPath))
                return CompletableFuture.failedFuture(failure);
            return CompletableFuture.completedFuture(utf8("wrapped:" + path.getFileName()));
        }
    }

    @Test
    void build_ReadsEveryKeyFileThroughTheKeyWrapper_NotItsOwnFileIo() {
        var wrapper = new ReadingKeyWrapper();
        var factory = new TestKeys.RecordingCryptoProviderFactory();
        var v1 = directory.resolve("not-on-disk-v1.bin");
        var v2 = directory.resolve("not-on-disk-v2.bin");

        try (var ignored = await(new KeyRingBuilder().withKeyWrapper(wrapper).withCryptoProviderFactory(factory).withKeyRefreshInterval(60)
                .withKeyFile(2, v2).withKeyFile(1, v1).buildAsync())) {
            assertEquals(List.of(v1, v2), wrapper.reads);
            assertArrayEquals(utf8("wrapped:not-on-disk-v1.bin"), factory.createdWrapped.get(0));
            assertArrayEquals(utf8("wrapped:not-on-disk-v2.bin"), factory.createdWrapped.get(1));
        }
    }

    @Test
    void build_WhenTheKeyWrapperRefusesAKeyFile_FailsWithItsException_AndClosesWhatItCreated() {
        var wrapper = new ReadingKeyWrapper();
        wrapper.failingPath = directory.resolve("v2.bin");
        wrapper.failure = new InvalidKeyFileException("Key file 'v2.bin' was refused by the native library with status -37 (...).");
        var factory = new TestKeys.RecordingCryptoProviderFactory();

        var thrown = awaitFailure(InvalidKeyFileException.class, new KeyRingBuilder().withKeyWrapper(wrapper).withCryptoProviderFactory(factory)
                .withKeyRefreshInterval(60).withEphemeralKey(5)
                .withKeyFile(1, directory.resolve("v1.bin"))
                .withKeyFile(2, wrapper.failingPath)
                .buildAsync());

        assertSame(wrapper.failure, thrown);
        assertEquals(1, factory.createdProviders.size());
        assertClosed(factory.createdProviders.getFirst());
    }

    @Test
    void build_WithAWrapperUsingTheDefaultRead_ReadsTheFileFromDisk() throws IOException {
        // TestKeys.FakeKeyWrapper doesn't override readKeyFileAsync: the interface's default reads.
        var content = utf8("wrapped-by-default");
        var path = keyFile("v1.bin", content);
        var factory = new TestKeys.RecordingCryptoProviderFactory();

        try (var ignored = await(configured(factory).withKeyFile(1, path).buildAsync())) {
            assertArrayEquals(content, factory.createdWrapped.getFirst());
        }
    }
}
