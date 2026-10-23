package io.github.runsecure.hkdfguard.springboot;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import io.github.runsecure.hkdfguard.abstractions.CryptoProviderFactory;
import io.github.runsecure.hkdfguard.abstractions.DataEncryptionKey;
import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.abstractions.VersionedKey;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.options.HkdfGuardOptions;
import io.github.runsecure.hkdfguard.options.KeyFileOptions;
import io.github.runsecure.hkdfguard.options.OptionsValidationException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.ConfigurationPropertiesAutoConfiguration;
import org.springframework.boot.health.contributor.Status;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

class HkdfGuardAutoConfigurationTest {
    /** Reveals and "generates" one fixed key, so a real ring builds without the native KMS. */
    static class FixedKeyWrapper implements KeyWrapper {
        private final byte[] key = new byte[32];

        FixedKeyWrapper() {
            new SecureRandom().nextBytes(key);
        }

        @Override
        public CompletableFuture<Integer> wrapAsync(byte[] plaintext, byte[] result) {
            return CompletableFuture.failedFuture(new UnsupportedOperationException());
        }

        @Override
        public CompletableFuture<Integer> unwrapAsync(byte[] wrapped, byte[] result) {
            System.arraycopy(key, 0, result, 0, key.length);
            return CompletableFuture.completedFuture(key.length);
        }

        // Test double: plain file I/O. A real key wrapper must refuse a key file another account could
        // have written or replaced (the native one reads through hkdfguard_open_file).
        @Override
        public CompletableFuture<byte[]> readKeyFileAsync(java.nio.file.Path path) {
            try {
                return CompletableFuture.completedFuture(java.nio.file.Files.readAllBytes(path));
            } catch (java.io.IOException | RuntimeException e) {
                return CompletableFuture.failedFuture(e);
            }
        }

        @Override
        public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
            System.arraycopy(key, 0, result, 0, key.length);
            return CompletableFuture.completedFuture(key.length);
        }
    }

    /** A ring holding one key, standing in for an application's own KeyRing bean. */
    record SingleKeyRing(DataEncryptionKey key) implements KeyRing {
        @Override
        public int getCurrentVersion() {
            return 7;
        }

        @Override
        public VersionedKey getCurrent() {
            return new VersionedKey(7, key);
        }

        @Override
        public DataEncryptionKey get(int version) {
            return find(version).orElseThrow(NoSuchElementException::new);
        }

        @Override
        public Optional<DataEncryptionKey> find(int version) {
            return version == 7 ? Optional.of(key) : Optional.empty();
        }
    }

    /** A key whose provider has failed closed, as after too many failed refreshes. */
    static final class FailedClosedKey implements DataEncryptionKey {
        @Override
        public byte[] encrypt(byte[] plaintext) {
            throw new IllegalStateException("The key has failed closed.");
        }

        @Override
        public byte[] encrypt(byte[] plaintext, byte[] aad) {
            throw new IllegalStateException("The key has failed closed.");
        }

        @Override
        public int decrypt(byte[] ciphertext, byte[] result) {
            throw new IllegalStateException("The key has failed closed.");
        }

        @Override
        public int decrypt(byte[] ciphertext, byte[] aad, byte[] result) {
            throw new IllegalStateException("The key has failed closed.");
        }
    }

    /** A key that "decrypts" to zeros, whatever it encrypted. */
    static final class CorruptKey implements DataEncryptionKey {
        @Override
        public byte[] encrypt(byte[] plaintext) {
            return plaintext.clone();
        }

        @Override
        public byte[] encrypt(byte[] plaintext, byte[] aad) {
            return plaintext.clone();
        }

        @Override
        public int decrypt(byte[] ciphertext, byte[] result) {
            return ciphertext.length;
        }

        @Override
        public int decrypt(byte[] ciphertext, byte[] aad, byte[] result) {
            return ciphertext.length;
        }
    }

    private static final FilteredClassLoader WITHOUT_NATIVE_WRAPPER = new FilteredClassLoader("io.github.runsecure.hkdfguard.keywrapping");

    // The native wrapper is filtered out unless a test asks for it: creating it loads the real library.
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class, HkdfGuardAutoConfiguration.class,
                    HkdfGuardHealthAutoConfiguration.class))
            .withClassLoader(WITHOUT_NATIVE_WRAPPER);

    private final ApplicationContextRunner configured = runner
            .withBean(KeyWrapper.class, FixedKeyWrapper::new)
            .withPropertyValues("hkdfguard.service-name=com.example.orders", "hkdfguard.key-refresh-interval=60",
                    "hkdfguard.ephemeral-keys[0]=1", "hkdfguard.ephemeral-keys[1]=2");

    @TempDir
    Path directory;

    // --- The ring ------------------------------------------------------------------------------

    @Test
    void withoutAServiceNameNothingIsBuilt() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(HkdfGuardOptions.class);
            assertThat(context).hasSingleBean(CryptoProviderFactory.class);
            assertThat(context).doesNotHaveBean(KeyRing.class);
            assertThat(context).doesNotHaveBean(KeyWrapper.class);
            assertThat(context).doesNotHaveBean(HkdfGuardHealthIndicator.class);
        });
    }

    @Test
    void bindsKebabCasePropertiesOntoTheOptions() {
        runner.withPropertyValues("hkdfguard.max-refresh-failures=4", "hkdfguard.ephemeral-key-rotation-hours=12",
                        "hkdfguard.ephemeral-key-retention-hours=48", "hkdfguard.key-files[0].version=3", "hkdfguard.key-files[0].path=/etc/dek-v3.bin")
                .run(context -> {
                    var options = context.getBean(HkdfGuardOptions.class);
                    assertThat(options.getMaxRefreshFailures()).isEqualTo(4);
                    assertThat(options.getEphemeralKeyRotationHours()).isEqualTo(12);
                    assertThat(options.getEphemeralKeyRetentionHours()).isEqualTo(48);
                    assertThat(options.getKeyFiles()).containsExactly(new KeyFileOptions(3, "/etc/dek-v3.bin"));
                });
    }

    @Test
    void buildsTheRingFromPropertiesAndAKeyWrapperBean() {
        configured.run(context -> {
            assertThat(context).hasNotFailed();
            var ring = context.getBean(KeyRing.class);
            assertThat(ring).isInstanceOf(KeyRingImpl.class);
            assertThat(ring.getCurrentVersion()).isEqualTo(2);
            assertThat(context.getBean(CryptoProviderFactory.class)).isInstanceOf(AesGcmCryptoProviderFactoryImpl.class);

            var protector = ((KeyRingImpl) ring).createProtector("ConnectionStrings:Admin");
            var result = new char[64];
            var written = protector.decrypt(protector.encrypt("secret"), result);
            assertThat(new String(result, 0, written)).isEqualTo("secret");
        });
    }

    @Test
    void buildsKeyFileVersionsFromProperties() throws IOException {
        var keyFile = Files.write(directory.resolve("wrapped-dek-v5.bin"), "wrapped".getBytes(StandardCharsets.US_ASCII));
        runner.withBean(KeyWrapper.class, FixedKeyWrapper::new)
                .withPropertyValues("hkdfguard.service-name=com.example.orders", "hkdfguard.key-refresh-interval=60",
                        "hkdfguard.key-files[0].version=5", "hkdfguard.key-files[0].path=" + keyFile)
                .run(context -> assertThat(context.getBean(KeyRing.class).getCurrentVersion()).isEqualTo(5));
    }

    @Test
    void closingTheContextClosesTheRing() {
        var ring = new KeyRing[1];
        configured.run(context -> ring[0] = context.getBean(KeyRing.class));

        var key = ring[0].getCurrent().key();
        assertThatThrownBy(() -> key.encrypt(new byte[] {1})).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void invalidOptionsFailStartupListingEveryProblem() {
        configured.withPropertyValues("hkdfguard.key-refresh-interval=0", "hkdfguard.max-refresh-failures=0").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).rootCause()
                    .isInstanceOf(OptionsValidationException.class)
                    .satisfies(e -> assertThat(((OptionsValidationException) e).getFailures()).containsExactly(
                            "keyRefreshInterval must be between 1 and 300 seconds.", "maxRefreshFailures must be at least 1."));
        });
    }

    @Test
    void anInvalidServiceNameFailsStartup() {
        configured.withPropertyValues("hkdfguard.service-name=bad..name")
                .run(context -> assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("can't contain '..'"));
    }

    @Test
    void anUnknownPropertyFailsStartup() {
        configured.withPropertyValues("hkdfguard.key-refresh-intreval=60")
                .run(context -> assertThat(context.getStartupFailure()).hasStackTraceContaining("key-refresh-intreval"));
    }

    @Test
    void aServiceNameWithoutAnyKeyWrapperFailsStartupSayingWhatToAdd() {
        runner.withPropertyValues("hkdfguard.service-name=com.example.orders", "hkdfguard.key-refresh-interval=60", "hkdfguard.ephemeral-keys[0]=1")
                .run(context -> assertThat(context.getStartupFailure()).rootCause()
                        .isInstanceOf(IllegalStateException.class)
                        .hasMessageContaining("there is no KeyWrapper")
                        .hasMessageContaining("declare a KeyWrapper bean"));
    }

    @Test
    void aKeyWrapperThatFailsFailsStartup() {
        runner.withBean(KeyWrapper.class, () -> new FixedKeyWrapper() {
                    // Test double: plain file I/O. A real key wrapper must refuse a key file another account could
                    // have written or replaced (the native one reads through hkdfguard_open_file).
                    @Override
                    public CompletableFuture<byte[]> readKeyFileAsync(java.nio.file.Path path) {
                        try {
                            return CompletableFuture.completedFuture(java.nio.file.Files.readAllBytes(path));
                        } catch (java.io.IOException | RuntimeException e) {
                            return CompletableFuture.failedFuture(e);
                        }
                    }

                    @Override
                    public CompletableFuture<Integer> generateAndWrapAsync(byte[] result) {
                        return CompletableFuture.failedFuture(new SecurityException("The KEK is not provisioned."));
                    }
                })
                .withPropertyValues("hkdfguard.service-name=com.example.orders", "hkdfguard.key-refresh-interval=60", "hkdfguard.ephemeral-keys[0]=1")
                .run(context -> assertThat(context.getStartupFailure()).rootCause().hasMessage("The KEK is not provisioned."));
    }

    @Test
    void anApplicationsOwnBeansReplaceTheDefaults() {
        var options = new HkdfGuardOptions();
        var factory = new AesGcmCryptoProviderFactoryImpl();
        var ring = new SingleKeyRing(new CorruptKey());
        runner.withBean(HkdfGuardOptions.class, () -> options)
                .withBean(CryptoProviderFactory.class, () -> factory)
                .withBean(KeyRing.class, () -> ring)
                .withPropertyValues("hkdfguard.service-name=com.example.orders")
                .run(context -> {
                    assertThat(context.getBean(HkdfGuardOptions.class)).isSameAs(options);
                    assertThat(context.getBean(CryptoProviderFactory.class)).isSameAs(factory);
                    assertThat(context.getBean(KeyRing.class)).isSameAs(ring);
                });
    }

    @Test
    void createsTheNativeKeyWrapperForTheServiceWhenItsLibraryIsInstalled() {
        // Creating the native wrapper loads and verifies the real library, so this runs only where
        // it is installed. The ring itself is the application's, so nothing calls the KMS.
        assumeTrue(System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows")
                && Files.isRegularFile(Path.of(System.getenv("ProgramFiles"), "HkdfGuard", "v1", "HkdfGuard.dll")),
                "The Windows native KMS library is not installed.");

        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(ConfigurationPropertiesAutoConfiguration.class, HkdfGuardAutoConfiguration.class))
                .withBean(KeyRing.class, () -> new SingleKeyRing(new CorruptKey()))
                .withPropertyValues("hkdfguard.service-name=com.example.orders")
                .run(context -> assertThat(context.getBean(KeyWrapper.class).getClass().getName())
                        .isEqualTo(HkdfGuardAutoConfiguration.NATIVE_KEY_WRAPPER_CLASS));
    }

    @Test
    void theNativeKeyWrapperIsSkippedWhenItsClassIsUnavailable() {
        runner.withPropertyValues("hkdfguard.service-name=com.example.orders")
                .withBean(KeyRing.class, () -> new SingleKeyRing(new CorruptKey()))
                .run(context -> assertThat(context).doesNotHaveBean(KeyWrapper.class));
    }

    // --- Health --------------------------------------------------------------------------------

    @Test
    void healthIsUpAndNamesTheCurrentVersion() {
        configured.run(context -> {
            var health = context.getBean("hkdfguardHealthIndicator", HkdfGuardHealthIndicator.class).health();
            assertThat(health.getStatus()).as(health.getDetails().toString()).isEqualTo(Status.UP);
            assertThat(health.getDetails()).containsExactlyEntriesOf(Map.of("currentVersion", 2));
        });
    }

    @Test
    void healthIsDownWhenTheCurrentKeyHasFailedClosed() {
        var health = new HkdfGuardHealthIndicator(new SingleKeyRing(new FailedClosedKey())).health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("currentVersion", 7);
        assertThat(String.valueOf(health.getDetails().get("error"))).contains("The key has failed closed.");
    }

    @Test
    void healthIsDownWhenTheCurrentKeyDoesNotRoundTrip() {
        var health = new HkdfGuardHealthIndicator(new SingleKeyRing(new CorruptKey())).health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails()).containsEntry("error", "The current key did not decrypt what it encrypted.");
    }

    @Test
    void healthIsDownAfterTheRingCloses() {
        var ring = new KeyRing[1];
        configured.run(context -> ring[0] = context.getBean(KeyRing.class));

        assertThat(new HkdfGuardHealthIndicator(ring[0]).health().getStatus()).isEqualTo(Status.DOWN);
    }

    @Test
    void healthCoversAnApplicationsOwnRing() {
        runner.withBean(KeyRing.class, () -> new SingleKeyRing(new FailedClosedKey()))
                .run(context -> assertThat(context.getBean(HkdfGuardHealthIndicator.class).health().getStatus()).isEqualTo(Status.DOWN));
    }

    @Test
    void healthCanBeTurnedOff() {
        configured.withPropertyValues("management.health.hkdfguard.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(HkdfGuardHealthIndicator.class));
    }

    @Test
    void healthIsSkippedWithoutActuator() {
        configured.withClassLoader(new FilteredClassLoader("io.github.runsecure.hkdfguard.keywrapping", "org.springframework.boot.health"))
                .run(context -> {
                    assertThat(context).hasSingleBean(KeyRing.class);
                    assertThat(context).doesNotHaveBean("hkdfguardHealthIndicator");
                });
    }

    @Test
    void theNullRingIsRejected() {
        assertThatThrownBy(() -> new HkdfGuardHealthIndicator(null)).isInstanceOf(NullPointerException.class);
    }
}
