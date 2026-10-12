package io.github.runsecure.hkdfguard.springboot;

import static io.github.runsecure.hkdfguard.springboot.TestKeyWrappers.ring;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.AuthenticationTagMismatchException;
import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatException;
import io.github.runsecure.hkdfguard.abstractions.ProtectedConfigurationPurpose;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmPipelineDataProtectorImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.cache.ProtectedCacheCollectionImpl;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.env.SystemEnvironmentPropertySource;

class ProtectedEnvironmentTest {
    private final KeyRingImpl ring = ring();
    private final Map<String, Object> values = new HashMap<>();
    private final StandardEnvironment environment = new StandardEnvironment();
    private final ProtectedEnvironment sut = new ProtectedEnvironment(environment, ring);

    ProtectedEnvironmentTest() {
        environment.getPropertySources().addFirst(new MapPropertySource("test", values));
        ConfigurationPropertySources.attach(environment);
    }

    @AfterEach
    void closeRing() {
        ring.close();
    }

    private String encrypt(String name, String plaintext) {
        return ring.createProtector(ProtectedConfigurationPurpose.forKey(name)).encrypt(plaintext);
    }

    private void protect(String name, String plaintext) {
        values.put(name, encrypt(name, plaintext));
    }

    private String decryptToString(String name) {
        var result = new char[8192];
        var written = sut.decrypt(name, result);
        return new String(result, 0, written);
    }

    // --- Revealing values ----------------------------------------------------------------------

    @Test
    void decryptChars_WithAKnownName_RoundTrips() {
        protect("spring.datasource.password", "Server=db;Password=hunter2");

        var result = new char[64];
        var written = sut.decrypt("spring.datasource.password", result);

        assertEquals("Server=db;Password=hunter2", new String(result, 0, written));
    }

    @Test
    void decryptBytes_WithAKnownName_RoundTrips() {
        protect("secrets.api-key", "top-secret-api-key");

        var result = new byte[64];
        var written = sut.decrypt("secrets.api-key", result);

        assertEquals("top-secret-api-key", new String(result, 0, written, StandardCharsets.UTF_8));
    }

    @Test
    void decryptChars_HandlesMultiByteUtf8() {
        var plaintext = "héllo wörld 日本語 🔐";
        protect("secret", plaintext);

        var result = new char[plaintext.length()];
        var written = sut.decrypt("secret", result);

        assertEquals(plaintext, new String(result, 0, written));
    }

    @Test
    void decryptBytes_HandlesMultiByteUtf8() {
        var plaintext = "héllo wörld 日本語 🔐";
        protect("secret", plaintext);

        var result = new byte[sut.findMaxDecryptedLength("secret").orElseThrow()];
        var written = sut.decrypt("secret", result);

        assertArrayEquals(plaintext.getBytes(StandardCharsets.UTF_8), java.util.Arrays.copyOf(result, written));
    }

    @Test
    void decrypt_WithAnUnknownName_ReturnsZeroForBothOverloads() {
        assertEquals(0, sut.decrypt("missing", new char[16]));
        assertEquals(0, sut.decrypt("missing", new byte[16]));
    }

    @Test
    void findMaxDecryptedLength_WithAKnownName_IsASafeUpperBoundForCharsAndBytes() {
        protect("secret", "some plaintext value é 日本");

        var maxLength = sut.findMaxDecryptedLength("secret").orElseThrow();

        assertTrue(maxLength >= sut.decrypt("secret", new char[maxLength]));
        assertTrue(maxLength >= sut.decrypt("secret", new byte[maxLength]));
    }

    @Test
    void findMaxDecryptedLength_WithAnUnknownName_IsEmpty() {
        assertTrue(sut.findMaxDecryptedLength("missing").isEmpty());
    }

    @Test
    void decrypt_WithAMalformedValue_ThrowsForBothOverloads() {
        values.put("bad", "not-a-protected-value");

        assertThrows(EncryptedFormatException.class, () -> sut.decrypt("bad", new char[16]));
        assertThrows(EncryptedFormatException.class, () -> sut.decrypt("bad", new byte[16]));
        assertThrows(EncryptedFormatException.class, () -> sut.findMaxDecryptedLength("bad"));
    }

    @Test
    void decryptBytes_IntoATooSmallBuffer_ThrowsAndLeavesNoPlaintextBehind() {
        protect("secret", "a value of some length");

        var result = new byte[5];
        assertThrows(IllegalArgumentException.class, () -> sut.decrypt("secret", result));
        assertArrayEquals(new byte[5], result);
    }

    @Test
    void decrypt_WithSensitiveLoggingEnabled_StillRoundTrips() {
        var telemetry = HkdfGuardTelemetry.ENCRYPTED_CONFIGURATION;
        var original = telemetry.isSensitiveLoggingEnabled();
        try {
            telemetry.setSensitiveLoggingEnabled(true);
            protect("secret", "top secret");

            assertEquals("top secret", decryptToString("secret"));
            var bytes = new byte[32];
            assertEquals("top secret", new String(bytes, 0, sut.decrypt("secret", bytes), StandardCharsets.UTF_8));
        } finally {
            telemetry.setSensitiveLoggingEnabled(original);
        }
    }

    @Test
    void nullArgumentsAreRejected() {
        assertThrows(NullPointerException.class, () -> new ProtectedEnvironment(null, ring));
        assertThrows(NullPointerException.class, () -> new ProtectedEnvironment(environment, null));
        assertThrows(NullPointerException.class, () -> sut.decrypt(null, new char[1]));
        assertThrows(NullPointerException.class, () -> sut.decrypt("secret", (char[]) null));
        assertThrows(NullPointerException.class, () -> sut.decrypt("secret", (byte[]) null));
    }

    // --- Reading the environment ---------------------------------------------------------------

    @Test
    void getProperty_StillYieldsTheCiphertext_NeverTheSecret() {
        protect("secret", "top secret");

        assertTrue(environment.getProperty("secret").startsWith("enc::v1::"));
    }

    @Test
    void everyCallReadsFresh_SoAChangedPropertyTakesEffectImmediately() {
        protect("secret", "first");
        assertEquals("first", decryptToString("secret"));

        protect("secret", "second");
        assertEquals("second", decryptToString("secret"));

        values.remove("secret");
        assertEquals(0, sut.decrypt("secret", new char[16]));
    }

    @Test
    void aValueFromAnEnvironmentVariable_DecryptsByItsCanonicalName() {
        // The pipeline encrypts for the name the application reads; Spring maps the variable to it.
        environment.getPropertySources().addFirst(new SystemEnvironmentPropertySource("variables",
                Map.of("MY_SERVICE_API_KEY", encrypt("my-service.api-key", "from-a-variable"))));

        assertEquals("from-a-variable", decryptToString("my-service.api-key"));
    }

    @Test
    void anotherSpellingThatSpringResolvesToTheSameValue_FailsAuthentication() {
        // Spring finds this value as "my-service.apikey" too, but it is bound to the name it was
        // encrypted for: reading it under another spelling fails rather than guessing.
        protect("my-service.api-key", "api-secret");

        assertEquals("api-secret", decryptToString("my-service.api-key"));
        assertThrows(AuthenticationTagMismatchException.class, () -> sut.decrypt("my-service.apikey", new char[64]));
    }

    @Test
    void worksAsASourceInAProtectedCacheCollection() {
        protect("secret", "from-configuration");
        var collection = new ProtectedCacheCollectionImpl().add(sut);

        var result = new char[64];
        assertEquals("from-configuration", new String(result, 0, collection.decrypt("secret", result)));
        assertEquals(0, collection.decrypt("missing", result));
    }

    // --- Binding each value to its name --------------------------------------------------------

    @Test
    void aValueCopiedToAnotherProperty_FailsAuthenticationForBothOverloads() {
        var adminValue = encrypt("connection-strings.admin", "admin-secret");
        values.put("connection-strings.admin", adminValue);
        values.put("connection-strings.reporting", adminValue); // an attacker swapped the admin value in

        assertEquals("admin-secret", decryptToString("connection-strings.admin"));
        assertThrows(AuthenticationTagMismatchException.class, () -> sut.decrypt("connection-strings.reporting", new char[64]));
        assertThrows(AuthenticationTagMismatchException.class, () -> sut.decrypt("connection-strings.reporting", new byte[64]));
    }

    @Test
    void aValueWrittenUnderTheOldSharedPurpose_NoLongerDecrypts() {
        values.put("secret", ring.createProtector(ProtectedConfigurationPurpose.PREFIX).encrypt("secret"));

        assertThrows(AuthenticationTagMismatchException.class, () -> sut.decrypt("secret", new char[64]));
    }

    @ParameterizedTest
    @ValueSource(strings = {"connectionstrings.admin", "CONNECTIONSTRINGS.ADMIN", "ConnectionStrings.Admin"})
    void theNameIsBoundIgnoringAsciiCase(String encryptedFor) {
        values.put("connectionstrings.admin", encrypt(encryptedFor, "admin-secret"));

        assertEquals("admin-secret", decryptToString("connectionstrings.admin"));
    }

    @Test
    void aValueMovedBetweenNamesThatOnlyUpperCaseAlike_FailsAuthentication() {
        // "ſecret" (long s) and "secret" are different names, though both upper-case to "SECRET"
        // under Java's own case rules - they must not share a purpose.
        var value = encrypt("secret", "real-secret");
        values.put("secret", value);
        values.put("ſecret", value);

        assertEquals("real-secret", decryptToString("secret"));
        assertThrows(AuthenticationTagMismatchException.class, () -> sut.decrypt("ſecret", new char[64]));
    }

    @Test
    void readsAValueWrittenByAPipelineDataProtectorForTheName() {
        try (var pipeline = new AesGcmPipelineDataProtectorImpl(new DefaultFormatProviderImpl(), 1)) {
            values.put("database.password", pipeline.encrypt("from-the-pipeline", "database.password"));
            var dek = Base64.getDecoder().decode(pipeline.getKeyAsBase64().toString());

            try (var pipelineRing = TestKeyWrappers.ringOver(dek, 1, new DefaultFormatProviderImpl())) {
                var result = new char[64];
                var written = new ProtectedEnvironment(environment, pipelineRing).decrypt("database.password", result);
                assertEquals("from-the-pipeline", new String(result, 0, written));
            }
        }
    }

    // --- Large values ----------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(ints = {1, 1500})
    void decryptBytes_ForSmallAndLargeValues_RoundTrips(int repeats) {
        // 1500 repeats is 15,000 UTF-8 bytes, mixing 1-, 2- and 3-byte characters.
        var plaintext = "é-秘密-".repeat(repeats);
        try (var bigRing = TestKeyWrappers.ringOver(TestKeyWrappers.randomKey(), 1, new DefaultFormatProviderImpl(100_000))) {
            values.put("big.secret", bigRing.createProtector(ProtectedConfigurationPurpose.forKey("big.secret")).encrypt(plaintext));
            var root = new ProtectedEnvironment(environment, bigRing);

            var result = new byte[root.findMaxDecryptedLength("big.secret").orElseThrow()];
            var written = root.decrypt("big.secret", result);

            assertEquals(plaintext, new String(result, 0, written, StandardCharsets.UTF_8));
        }
    }
}
