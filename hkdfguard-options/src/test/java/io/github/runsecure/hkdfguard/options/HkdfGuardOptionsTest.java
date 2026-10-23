package io.github.runsecure.hkdfguard.options;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.KeyWrapper;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingBuilder;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class HkdfGuardOptionsTest {
    /**
     * Always reveals and "generates" the same fixed key: isolates applyTo/build from the native KMS
     * while still running a real KeyRingBuilder build.
     */
    static final class FixedKeyWrapper implements KeyWrapper {
        private final byte[] key = new byte[32];

        FixedKeyWrapper() {
            new SecureRandom().nextBytes(key);
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

    @TempDir
    Path directory;

    private Path keyFile() throws IOException {
        return Files.write(directory.resolve("wrapped-dek-v1.bin"), "wrapped".getBytes(StandardCharsets.US_ASCII));
    }

    private static KeyRingImpl build(KeyRingBuilder builder) {
        return builder.withKeyWrapper(new FixedKeyWrapper())
                .withCryptoProviderFactory(new AesGcmCryptoProviderFactoryImpl())
                .withKeyRefreshInterval(60)
                .buildAsync()
                .join();
    }

    private static HkdfGuardOptions validOptions() {
        var options = new HkdfGuardOptions();
        options.setServiceName("my.service");
        options.setKeyRefreshInterval(60);
        options.setEphemeralKeys(List.of(1));
        return options;
    }

    private static boolean anyFailure(HkdfGuardOptions options, String fragment) {
        return options.validate().stream().anyMatch(f -> f.contains(fragment));
    }

    @Nested
    class ApplyTo {
        @Test
        void returnsTheSameBuilderForChaining() {
            var builder = new KeyRingBuilder();
            assertSame(builder, new HkdfGuardOptions().applyTo(builder));
        }

        @Test
        void setsServiceNameKeyRefreshIntervalAndMaxRefreshFailures() {
            var options = new HkdfGuardOptions();
            options.setServiceName("my.service");
            options.setKeyRefreshInterval(60);
            options.setMaxRefreshFailures(3);

            var builder = options.applyTo(new KeyRingBuilder());

            assertEquals("my.service", builder.getServiceName());
            assertEquals(60, builder.getKeyRefreshInterval());
            assertEquals(3, builder.getMaxRefreshFailures());
        }

        @Test
        void unsetFieldsLeaveTheBuilderDefaultsUntouched() {
            var builder = new HkdfGuardOptions().applyTo(new KeyRingBuilder());

            assertNull(builder.getServiceName());
            assertNull(builder.getKeyRefreshInterval());
            assertEquals(KeyRingBuilder.DEFAULT_MAX_REFRESH_FAILURES, builder.getMaxRefreshFailures());
            assertEquals(Duration.ofHours(24), builder.getEphemeralKeyRotationInterval());
            assertEquals(KeyRingBuilder.DEFAULT_EPHEMERAL_KEY_RETENTION, builder.getEphemeralKeyRetention());
        }

        @Test
        void ephemeralKeyRotationHoursSetsTheInterval() {
            var options = new HkdfGuardOptions();
            options.setEphemeralKeyRotationHours(6);
            assertEquals(Duration.ofHours(6), options.applyTo(new KeyRingBuilder()).getEphemeralKeyRotationInterval());
        }

        @Test
        void ephemeralKeyRetentionHoursSetsTheRetention() {
            var options = new HkdfGuardOptions();
            options.setEphemeralKeyRetentionHours(48);
            assertEquals(Duration.ofHours(48), options.applyTo(new KeyRingBuilder()).getEphemeralKeyRetention());
        }

        @Test
        void disableEphemeralKeyRotationTurnsItOff() {
            var options = new HkdfGuardOptions();
            options.setDisableEphemeralKeyRotation(true);
            assertNull(options.applyTo(new KeyRingBuilder()).getEphemeralKeyRotationInterval());
        }

        @Test
        void failOpenOnRefreshFailureClearsTheBuildersPolicy() {
            var options = new HkdfGuardOptions();
            options.setFailOpenOnRefreshFailure(true);
            assertNull(options.applyTo(new KeyRingBuilder()).getMaxRefreshFailures());
        }

        @Test
        void anOptionTheBuilderRejectsThrows() {
            // applyTo doesn't validate; the builder's own checks still hold.
            var options = new HkdfGuardOptions();
            options.setKeyRefreshInterval(0);
            assertThrows(IllegalArgumentException.class, () -> options.applyTo(new KeyRingBuilder()));
        }

        @Test
        void aNullBuilderThrows() {
            assertThrows(NullPointerException.class, () -> new HkdfGuardOptions().applyTo(null));
        }

        @Test
        void withEphemeralKeysRegistersEachOnBuild() {
            var options = new HkdfGuardOptions();
            options.setEphemeralKeys(List.of(1, 2));

            try (var ring = build(options.applyTo(new KeyRingBuilder()))) {
                assertEquals(2, ring.getCurrentVersion());
            }
        }

        @Test
        void withKeyFilesRegistersEachOnBuild() throws IOException {
            var options = new HkdfGuardOptions();
            options.setKeyFiles(List.of(new KeyFileOptions(1, keyFile().toString())));

            try (var ring = build(options.applyTo(new KeyRingBuilder()))) {
                assertEquals(1, ring.getCurrentVersion());
            }
        }

        @Test
        void withKeyFilesAndEphemeralKeysTheHighestVersionBecomesCurrent() throws IOException {
            var options = new HkdfGuardOptions();
            options.setKeyFiles(List.of(new KeyFileOptions(1, keyFile().toString())));
            options.setEphemeralKeys(List.of(2));

            try (var ring = build(options.applyTo(new KeyRingBuilder()))) {
                assertEquals(2, ring.getCurrentVersion());
            }
        }
    }

    @Nested
    class Validate {
        @Test
        void validOptionsHaveNoFailures() {
            assertEquals(List.of(), validOptions().validate());
        }

        static Stream<Arguments> serviceNamesBreakingARule() {
            return Stream.of(Arguments.of(".service", "can't start with '.'"), Arguments.of("my..service", "can't contain '..'"),
                    Arguments.of("my-service", "U+002D"));
        }

        @ParameterizedTest
        @MethodSource("serviceNamesBreakingARule")
        void aServiceNameBreakingARuleFailsWithTheReason(String serviceName, String reason) {
            var options = validOptions();
            options.setServiceName(serviceName);
            assertTrue(options.validate().stream().anyMatch(f -> f.startsWith("serviceName is invalid") && f.contains(reason)));
        }

        @Test
        void aServiceNameOverTheLimitFails() {
            var options = validOptions();
            options.setServiceName("a".repeat(129));
            assertFalse(options.validate().isEmpty());
        }

        @ParameterizedTest
        @NullAndEmptySource
        @ValueSource(strings = "   ")
        void aMissingServiceNameFails(String serviceName) {
            var options = validOptions();
            options.setServiceName(serviceName);
            assertTrue(anyFailure(options, "serviceName"));
        }

        @ParameterizedTest
        @ValueSource(ints = {-1, 0, 301})
        void aKeyRefreshIntervalOutOfRangeFails(int interval) {
            var options = validOptions();
            options.setKeyRefreshInterval(interval);
            assertTrue(anyFailure(options, "keyRefreshInterval"));
        }

        @ParameterizedTest
        @ValueSource(ints = {1, 300})
        void aKeyRefreshIntervalInRangeSucceeds(int interval) {
            var options = validOptions();
            options.setKeyRefreshInterval(interval);
            assertEquals(List.of(), options.validate());
        }

        @Test
        void aKeyRefreshIntervalUnsetSucceeds() {
            var options = validOptions();
            options.setKeyRefreshInterval(null);
            assertEquals(List.of(), options.validate());
        }

        @Test
        void noKeyFilesOrEphemeralKeysFails() {
            var options = validOptions();
            options.setEphemeralKeys(List.of());
            assertTrue(anyFailure(options, "key file or ephemeral key"));
        }

        @ParameterizedTest
        @ValueSource(strings = {"", "   "})
        void aKeyFileWithoutAPathFails(String path) {
            var options = validOptions();
            options.setEphemeralKeys(List.of());
            options.setKeyFiles(List.of(new KeyFileOptions(1, path)));
            assertTrue(anyFailure(options, "missing a path"));
        }

        @Test
        void aVersionRegisteredTwiceAcrossKeyFilesAndEphemeralKeysFails() {
            var options = validOptions();
            options.setKeyFiles(List.of(new KeyFileOptions(1, "/tmp/dek.bin")));
            assertTrue(anyFailure(options, "Version 1 is registered more than once"));
        }

        @Test
        void aVersionRepeatedWithinEphemeralKeysFails() {
            var options = validOptions();
            options.setEphemeralKeys(List.of(1, 1));
            assertTrue(anyFailure(options, "more than once"));
        }

        @Test
        void uniqueVersionsAcrossKeyFilesAndEphemeralKeysSucceed() {
            var options = validOptions();
            options.setEphemeralKeys(List.of(2));
            options.setKeyFiles(List.of(new KeyFileOptions(1, "/tmp/dek.bin")));
            assertEquals(List.of(), options.validate());
        }

        @Test
        void aKeyFileAboveEveryEphemeralKeyWithRotationOnFails() {
            // The first rotation would replace the key file as current with a key lost on restart.
            var options = validOptions();
            options.setKeyFiles(List.of(new KeyFileOptions(3, "/tmp/dek.bin")));
            assertTrue(anyFailure(options, "Key file version 3 is above every ephemeral version"));
        }

        @Test
        void aKeyFileAboveEveryEphemeralKeyWithRotationDisabledSucceeds() {
            var options = validOptions();
            options.setKeyFiles(List.of(new KeyFileOptions(3, "/tmp/dek.bin")));
            options.setDisableEphemeralKeyRotation(true);
            assertEquals(List.of(), options.validate());
        }

        @Test
        void aNullKeyFileOrEphemeralKeyEntryFails() {
            // A binder can leave a gap in a list; applying it would otherwise fail deep in the builder.
            var options = validOptions();
            options.setKeyFiles(Arrays.asList(new KeyFileOptions(2, "a.bin"), null));
            options.setEphemeralKeys(Arrays.asList(3, null));

            assertEquals(List.of("keyFiles[1] is missing.", "ephemeralKeys[1] is missing."), options.validate());
        }

        @ParameterizedTest
        @ValueSource(ints = {0, -1, 101, Integer.MAX_VALUE})
        void maxRefreshFailuresOutsideOneToOneHundredFails(int failures) {
            var options = validOptions();
            options.setMaxRefreshFailures(failures);
            assertTrue(anyFailure(options, "maxRefreshFailures"));
        }

        @ParameterizedTest
        @ValueSource(ints = {1, 10, 100})
        void maxRefreshFailuresFromOneToOneHundredSucceeds(int failures) {
            var options = validOptions();
            options.setMaxRefreshFailures(failures);
            assertEquals(List.of(), options.validate());
        }

        @Test
        void maxRefreshFailuresUnsetSucceeds() {
            var options = validOptions();
            options.setMaxRefreshFailures(null);
            assertEquals(List.of(), options.validate());
        }

        @ParameterizedTest
        @ValueSource(ints = {1, 24, HkdfGuardOptions.MAX_EPHEMERAL_KEY_ROTATION_HOURS})
        void ephemeralKeyRotationHoursInRangeSucceed(int hours) {
            var options = validOptions();
            options.setEphemeralKeyRotationHours(hours);

            assertEquals(List.of(), options.validate());
            assertDoesNotThrow(() -> options.applyTo(new KeyRingBuilder())); // and the builder accepts every hour validation does
        }

        @ParameterizedTest
        @ValueSource(ints = {0, -1, HkdfGuardOptions.MAX_EPHEMERAL_KEY_ROTATION_HOURS + 1})
        void ephemeralKeyRotationHoursOutOfRangeFail(int hours) {
            var options = validOptions();
            options.setEphemeralKeyRotationHours(hours);
            assertTrue(anyFailure(options, "ephemeralKeyRotationHours"));
        }

        @Test
        void theRotationHourLimitIsTheBuildersLimit() {
            var limit = Duration.ofHours(HkdfGuardOptions.MAX_EPHEMERAL_KEY_ROTATION_HOURS);
            assertTrue(limit.compareTo(KeyRingBuilder.MAX_EPHEMERAL_KEY_ROTATION_INTERVAL) <= 0);
            assertTrue(limit.plusHours(1).compareTo(KeyRingBuilder.MAX_EPHEMERAL_KEY_ROTATION_INTERVAL) > 0);
        }

        @ParameterizedTest
        @ValueSource(ints = {1, 24, 24 * 365})
        void ephemeralKeyRetentionHoursAtLeastOneSucceed(int hours) {
            var options = validOptions();
            options.setEphemeralKeyRetentionHours(hours);

            assertEquals(List.of(), options.validate());
            assertEquals(Duration.ofHours(hours), options.applyTo(new KeyRingBuilder()).getEphemeralKeyRetention());
        }

        @ParameterizedTest
        @ValueSource(ints = {0, -1})
        void ephemeralKeyRetentionHoursBelowOneFail(int hours) {
            var options = validOptions();
            options.setEphemeralKeyRetentionHours(hours);
            assertTrue(anyFailure(options, "ephemeralKeyRetentionHours"));
        }

        @Test
        void disablingRotationWhileSchedulingItFails() {
            var options = validOptions();
            options.setDisableEphemeralKeyRotation(true);
            options.setEphemeralKeyRotationHours(12);
            assertTrue(anyFailure(options, "disableEphemeralKeyRotation"));
        }

        @Test
        void disablingRotationAloneSucceeds() {
            var options = validOptions();
            options.setDisableEphemeralKeyRotation(true);
            assertEquals(List.of(), options.validate());
        }

        @Test
        void failOpenAloneSucceeds() {
            var options = validOptions();
            options.setFailOpenOnRefreshFailure(true);
            assertEquals(List.of(), options.validate());
        }

        @Test
        void failOpenWithMaxRefreshFailuresFails() {
            var options = validOptions();
            options.setFailOpenOnRefreshFailure(true);
            options.setMaxRefreshFailures(3);
            assertTrue(anyFailure(options, "failOpenOnRefreshFailure"));
        }

        @Test
        void validateReportsEveryFailureAtOnce() {
            var options = new HkdfGuardOptions();
            options.setServiceName("bad..name");
            options.setKeyRefreshInterval(0);
            options.setMaxRefreshFailures(0);

            assertEquals(4, options.validate().size()); // service name, interval, max failures, and no keys
        }

        @Test
        void requireValidReturnsTheSameOptions() {
            var options = validOptions();
            assertSame(options, options.requireValid());
        }

        @Test
        void requireValidThrowsWithEveryFailure() {
            var options = new HkdfGuardOptions();
            options.setKeyRefreshInterval(0);

            var thrown = assertThrows(OptionsValidationException.class, options::requireValid);

            assertEquals(3, thrown.getFailures().size());
            assertInstanceOf(IllegalArgumentException.class, thrown);
            assertTrue(thrown.getMessage().contains("keyRefreshInterval must be between 1 and 300 seconds."));
        }
    }

    @Nested
    class Properties {
        @Test
        void listSettersCopyAndTreatNullAsEmpty() {
            var options = new HkdfGuardOptions();
            var versions = new ArrayList<>(List.of(1));
            options.setEphemeralKeys(versions);
            versions.add(2);
            options.setKeyFiles(null);

            assertEquals(List.of(1), options.getEphemeralKeys());
            assertEquals(List.of(), options.getKeyFiles());
        }

        @Test
        void listGettersAreLiveForBindersThatAddToThem() {
            var options = new HkdfGuardOptions();
            options.getEphemeralKeys().add(1);
            options.getKeyFiles().add(new KeyFileOptions(2, "a.bin"));

            assertEquals(List.of(1), options.getEphemeralKeys());
            assertEquals(List.of(new KeyFileOptions(2, "a.bin")), options.getKeyFiles());
        }

        @Test
        void keyFileOptionsIsABeanWithANeverNullPath() {
            var keyFile = new KeyFileOptions();
            assertEquals(0, keyFile.getVersion());
            assertEquals("", keyFile.getPath());

            keyFile.setVersion(3);
            keyFile.setPath(null);
            assertEquals(new KeyFileOptions(3, ""), keyFile);
            assertEquals(new KeyFileOptions(3, "").hashCode(), keyFile.hashCode());
            assertEquals("KeyFileOptions[version=3, path=]", keyFile.toString());
        }

        @Test
        void optionsCompareByValue() {
            assertEquals(validOptions(), validOptions());
            assertEquals(validOptions().hashCode(), validOptions().hashCode());
            assertFalse(validOptions().equals(new HkdfGuardOptions()));
            assertTrue(validOptions().toString().contains("serviceName=my.service"));
        }

        @Test
        void theValidationExceptionKeepsItsFailuresImmutable() {
            var exception = new OptionsValidationException(new ArrayList<>(List.of("a.", "b.")));
            assertEquals(List.of("a.", "b."), exception.getFailures());
            assertThrows(UnsupportedOperationException.class, () -> exception.getFailures().add("c."));
        }
    }

    @Nested
    class FromMap {
        @Test
        void readsADotnetAppsettingsSection() {
            // As Jackson or any JSON parser hands back appsettings.json's "HkdfGuard" section.
            var settings = Map.<String, Object>of(
                    "ServiceName", "com.example.orders",
                    "KeyRefreshInterval", 60,
                    "MaxRefreshFailures", 3,
                    "EphemeralKeyRotationHours", 12,
                    "EphemeralKeyRetentionHours", 48,
                    "KeyFiles", List.of(Map.of("Version", 1, "Path", "/etc/myapp/wrapped-dek-v1.bin")),
                    "EphemeralKeys", List.of(2));

            var options = HkdfGuardOptions.fromMap(settings);

            var expected = new HkdfGuardOptions();
            expected.setServiceName("com.example.orders");
            expected.setKeyRefreshInterval(60);
            expected.setMaxRefreshFailures(3);
            expected.setEphemeralKeyRotationHours(12);
            expected.setEphemeralKeyRetentionHours(48);
            expected.setKeyFiles(List.of(new KeyFileOptions(1, "/etc/myapp/wrapped-dek-v1.bin")));
            expected.setEphemeralKeys(List.of(2));
            assertEquals(expected, options);
            assertEquals(List.of(), options.validate());
        }

        @Test
        void readsSpringStyleKebabCaseAndSnakeCase() {
            var options = HkdfGuardOptions.fromMap(Map.of(
                    "service-name", "a.b",
                    "key_refresh_interval", 5,
                    "fail-open-on-refresh-failure", true,
                    "disable_ephemeral_key_rotation", true,
                    "ephemeralKeys", List.of(1)));

            assertEquals("a.b", options.getServiceName());
            assertEquals(5, options.getKeyRefreshInterval());
            assertTrue(options.isFailOpenOnRefreshFailure());
            assertTrue(options.isDisableEphemeralKeyRotation());
            assertEquals(List.of(1), options.getEphemeralKeys());
        }

        @Test
        void convertsStringsAsPropertiesFilesAndEnvironmentVariablesSupplyThem() {
            var options = HkdfGuardOptions.fromMap(Map.of(
                    "KeyRefreshInterval", " 60 ",
                    "MaxRefreshFailures", "+3",
                    "FailOpenOnRefreshFailure", "False",
                    "DisableEphemeralKeyRotation", "TRUE",
                    "EphemeralKeys", List.of("1", 2L),
                    "KeyFiles", List.of(Map.of("Version", "3", "Path", "k.bin"))));

            assertEquals(60, options.getKeyRefreshInterval());
            assertEquals(3, options.getMaxRefreshFailures());
            assertFalse(options.isFailOpenOnRefreshFailure());
            assertTrue(options.isDisableEphemeralKeyRotation());
            assertEquals(List.of(1, 2), options.getEphemeralKeys());
            assertEquals(List.of(new KeyFileOptions(3, "k.bin")), options.getKeyFiles());
        }

        @Test
        void acceptsEveryIntegralNumberType() {
            var options = HkdfGuardOptions.fromMap(Map.of("EphemeralKeys", List.of((byte) 1, (short) 2, 3, 4L, BigInteger.valueOf(5))));
            assertEquals(List.of(1, 2, 3, 4, 5), options.getEphemeralKeys());
        }

        @Test
        void treatsNullAsUnset() {
            var settings = new HashMap<String, Object>();
            for (var key : List.of("ServiceName", "KeyRefreshInterval", "FailOpenOnRefreshFailure", "KeyFiles", "EphemeralKeys"))
                settings.put(key, null);

            assertEquals(new HkdfGuardOptions(), HkdfGuardOptions.fromMap(settings));
        }

        @Test
        void anEmptySectionIsAllDefaults() {
            assertEquals(new HkdfGuardOptions(), HkdfGuardOptions.fromMap(Map.of()));
        }

        @Test
        void acceptsKeyFileOptionsAndPathObjects() {
            var options = HkdfGuardOptions.fromMap(Map.of("KeyFiles", List.of(new KeyFileOptions(1, "a.bin"), Map.of("Version", 2, "Path", Path.of("b.bin")))));
            assertEquals(List.of(new KeyFileOptions(1, "a.bin"), new KeyFileOptions(2, Path.of("b.bin").toString())), options.getKeyFiles());
        }

        @Test
        void leavesValidationToTheCaller() {
            assertTrue(anyFailure(HkdfGuardOptions.fromMap(Map.of("KeyRefreshInterval", 0)), "keyRefreshInterval"));
        }

        @Test
        void aKeyFileWithoutAPathReadsAndThenFailsValidation() {
            var options = HkdfGuardOptions.fromMap(Map.of("ServiceName", "a.b", "KeyFiles", List.of(Map.of("Version", 1))));
            assertEquals(List.of("keyFiles version 1 is missing a path."), options.validate());
        }

        @Test
        void thenRequireValidThenApplyToBuildsARing() throws IOException {
            var settings = Map.of("ServiceName", "my.service", "KeyRefreshInterval", 60,
                    "KeyFiles", List.of(Map.of("Version", 1, "Path", keyFile().toString())), "EphemeralKeys", List.of(2));

            var builder = HkdfGuardOptions.fromMap(settings).requireValid().applyTo(new KeyRingBuilder());
            try (var ring = builder.withKeyWrapper(new FixedKeyWrapper()).withCryptoProviderFactory(new AesGcmCryptoProviderFactoryImpl()).buildAsync().join()) {
                assertEquals(2, ring.getCurrentVersion());
            }
        }

        @Test
        void aNullSectionThrows() {
            assertThrows(NullPointerException.class, () -> HkdfGuardOptions.fromMap(null));
        }

        static Stream<Arguments> badSettings() {
            var twice = new LinkedHashMap<String, Object>();
            twice.put("ServiceName", "a.b");
            twice.put("service_name", "c.d");
            return Stream.of(
                    Arguments.of(Map.of("ServiceNmae", "a.b"), "settings has an unknown key 'ServiceNmae'"),
                    Arguments.of(twice, "settings gives 'serviceName' more than once"),
                    Arguments.of(Map.of("ServiceName", 5), "settings.serviceName must be a string; it is Integer"),
                    Arguments.of(Map.of("KeyRefreshInterval", "sixty"), "settings.keyRefreshInterval must be an integer; it is 'sixty'"),
                    Arguments.of(Map.of("KeyRefreshInterval", 60.5), "must be an integer; it is 60.5 (Double)"),
                    Arguments.of(Map.of("KeyRefreshInterval", true), "must be an integer"),
                    Arguments.of(Map.of("KeyRefreshInterval", 1L << 31), "settings.keyRefreshInterval is out of range for an integer"),
                    Arguments.of(Map.of("KeyRefreshInterval", "99999999999"), "out of range"),
                    Arguments.of(Map.of("FailOpenOnRefreshFailure", "yes"), "settings.failOpenOnRefreshFailure must be true or false"),
                    Arguments.of(Map.of("FailOpenOnRefreshFailure", 1), "must be true or false"),
                    Arguments.of(Map.of("EphemeralKeys", "1"), "settings.ephemeralKeys must be a list; it is String"),
                    Arguments.of(Map.of("EphemeralKeys", 1), "must be a list"),
                    Arguments.of(Map.of("EphemeralKeys", List.of(1, "x")), "settings.ephemeralKeys[1] must be an integer"),
                    Arguments.of(Map.of("EphemeralKeys", Arrays.asList(1, null)), "settings.ephemeralKeys[1] is missing"),
                    Arguments.of(Map.of("KeyFiles", List.of(Map.of("Path", "a.bin"))), "settings.keyFiles[0] is missing its version"),
                    Arguments.of(Map.of("KeyFiles", List.of(Map.of("Version", 1, "Path", 7))), "settings.keyFiles[0].path must be a path"),
                    Arguments.of(Map.of("KeyFiles", List.of(Map.of("Version", 1, "Path", "a", "Size", 3))), "settings.keyFiles[0] has an unknown key 'Size'"),
                    Arguments.of(Map.of("KeyFiles", List.of("a.bin")), "settings.keyFiles[0] must be a map; it is String"),
                    Arguments.of(Map.of("KeyFiles", List.of(Map.of(1, "a.bin"))), "settings.keyFiles[0] has a key that is not a string"));
        }

        @ParameterizedTest
        @MethodSource("badSettings")
        void rejectsBadSettingsNamingWhere(Map<String, ?> settings, String message) {
            var thrown = assertThrows(IllegalArgumentException.class, () -> HkdfGuardOptions.fromMap(settings));
            assertTrue(thrown.getMessage().contains(message), thrown.getMessage());
        }
    }
}
