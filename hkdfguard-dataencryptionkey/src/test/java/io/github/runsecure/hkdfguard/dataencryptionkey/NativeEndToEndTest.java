package io.github.runsecure.hkdfguard.dataencryptionkey;

import static io.github.runsecure.hkdfguard.dataencryptionkey.Futures.await;
import static io.github.runsecure.hkdfguard.dataencryptionkey.Futures.awaitFailure;
import static io.github.runsecure.hkdfguard.dataencryptionkey.Futures.sleep;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.AuthenticationTagMismatchException;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import io.github.runsecure.hkdfguard.abstractions.ProtectedConfigurationPurpose;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmPipelineDataProtectorImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import io.github.runsecure.hkdfguard.keywrapping.v1.NativeHkdfKeyWrapperV1Impl;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * End to end over the real native KEK: a pipeline encrypting configuration through to the
 * application reading it back, and the runtime keys a process generates for itself. Runs against
 * HKDFGUARD_TEST_SERVICE, or on Windows the provisioned test KEK com.hkdfguard.native.windows.test;
 * reported as skipped where there is none.
 */
class NativeEndToEndTest {
    private static final int KEY_FILE_VERSION = 3;
    private static final String UNPROVISIONED = "hkdfguard.integrationtest.unprovisioned";

    private static String service;

    @TempDir
    Path directory;

    @BeforeAll
    static void requireAProvisionedService() {
        var explicit = System.getenv("HKDFGUARD_TEST_SERVICE");
        if (explicit != null && !explicit.isEmpty()) {
            service = explicit;
            return;
        }

        Assumptions.assumeTrue(System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows"),
                "Set HKDFGUARD_TEST_SERVICE to a provisioned service to run native end-to-end tests.");
        var candidate = "com.hkdfguard.native.windows.test";
        try {
            new NativeHkdfKeyWrapperV1Impl(candidate).generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]).get();
        } catch (ExecutionException | InterruptedException e) {
            var message = String.valueOf(e.getCause() == null ? e : e.getCause().getMessage());
            // Not installed, not provisioned, or not permitted: skip. Anything else is a real failure.
            Assumptions.assumeFalse(message.contains("not installed") || message.contains("status -17") || message.contains("status -18"),
                    "The Windows test KEK is unavailable: " + message
                            + " Run scripts/provision-windows-test-key.ps1 from an elevated PowerShell, or set HKDFGUARD_TEST_SERVICE to a provisioned service.");
        }
        service = candidate;
    }

    private static KeyRingBuilder ringBuilder(String serviceName) {
        return new KeyRingBuilder()
                .withServiceName(serviceName)
                .withKeyWrapper(new NativeHkdfKeyWrapperV1Impl(serviceName))
                .withCryptoProviderFactory(new AesGcmCryptoProviderFactoryImpl())
                .withKeyRefreshInterval(60);
    }

    private record Release(Path keyFile, Map<String, String> configuration) {
    }

    // What the release pipeline does: protect configuration under a fresh in-memory key, then hand
    // that key to the native KEK and write the wrapped result as the release's key file.
    private Release runPipeline(String... keysAndSecrets) throws Exception {
        try (var pipeline = new AesGcmPipelineDataProtectorImpl(new DefaultFormatProviderImpl(), KEY_FILE_VERSION)) {
            var configuration = new LinkedHashMap<String, String>();
            for (var i = 0; i < keysAndSecrets.length; i += 2)
                configuration.put(keysAndSecrets[i], pipeline.encrypt(keysAndSecrets[i + 1], keysAndSecrets[i]));

            var dek = Base64.getDecoder().decode(pipeline.getKeyAsBase64().toString());
            try {
                var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
                int length = new NativeHkdfKeyWrapperV1Impl(service).wrapAsync(dek, wrapped).get();
                // By its real, long path: the native library refuses a key file path with an 8.3
                // short name or a link in it, and the temp folder can be handed out in short form.
                var path = Files.write(directory.toRealPath().resolve("wrapped-dek-v" + KEY_FILE_VERSION + ".bin"), Arrays.copyOf(wrapped, length));
                return new Release(path, configuration);
            } finally {
                ArrayUtility.zeroMemory(dek);
            }
        }
    }

    // What a configuration reader does: one protector per configuration key's purpose.
    private static String read(KeyRingImpl ring, Map<String, String> configuration, String key) {
        DataProtector protector = ring.createProtector(ProtectedConfigurationPurpose.forKey(key));
        var formatted = configuration.get(key);
        var result = new char[protector.getMaxDecryptedLength(formatted)];
        return new String(result, 0, protector.decrypt(formatted, result));
    }

    @Test
    void aDeployment_PipelineEncryptedConfiguration_DecryptsThroughItsNativelyWrappedKeyFile() throws Exception {
        var release = runPipeline("ConnectionStrings:Admin", "Server=db;User=admin;Password=s3cret", "Api:Key", "k-0123456789abcdef");

        try (var ring = await(ringBuilder(service).withKeyFile(KEY_FILE_VERSION, release.keyFile()).buildAsync())) {
            assertEquals("Server=db;User=admin;Password=s3cret", read(ring, release.configuration(), "ConnectionStrings:Admin"));
            assertEquals("k-0123456789abcdef", read(ring, release.configuration(), "Api:Key"));
        }
    }

    @Test
    void aDeployment_ValuesMovedToAnotherKey_FailAuthentication() throws Exception {
        var release = runPipeline("ConnectionStrings:Admin", "admin-only", "ConnectionStrings:Reports", "reports");
        release.configuration().put("ConnectionStrings:Reports", release.configuration().get("ConnectionStrings:Admin"));

        try (var ring = await(ringBuilder(service).withKeyFile(KEY_FILE_VERSION, release.keyFile()).buildAsync())) {
            assertThrows(AuthenticationTagMismatchException.class, () -> read(ring, release.configuration(), "ConnectionStrings:Reports"));
        }
    }

    @Test
    void aRestart_ReadingTheSameKeyFile_RevealsTheSameKey() throws Exception {
        var release = runPipeline("Secret", "survives a restart");

        try (var first = await(ringBuilder(service).withKeyFile(KEY_FILE_VERSION, release.keyFile()).buildAsync())) {
            assertEquals("survives a restart", read(first, release.configuration(), "Secret"));
        }
        try (var second = await(ringBuilder(service).withKeyFile(KEY_FILE_VERSION, release.keyFile()).buildAsync())) {
            assertEquals("survives a restart", read(second, release.configuration(), "Secret"));
        }
    }

    @Test
    void aKeyFile_WrappedUnderAnotherService_RefusesToBuild() throws Exception {
        var release = runPipeline("Secret", "value");

        awaitFailure(CryptographicException.class, ringBuilder(UNPROVISIONED).withKeyFile(KEY_FILE_VERSION, release.keyFile()).buildAsync());
    }

    @Test
    void aTamperedKeyFile_RefusesToBuild() throws Exception {
        var release = runPipeline("Secret", "value");
        var bytes = Files.readAllBytes(release.keyFile());
        bytes[bytes.length / 2] ^= 0x01;
        Files.write(release.keyFile(), bytes);

        awaitFailure(CryptographicException.class, ringBuilder(service).withKeyFile(KEY_FILE_VERSION, release.keyFile()).buildAsync());
    }

    @Test
    void aDeployedAndARuntimeKey_TogetherInOneRing_EachDoTheirJob() throws Exception {
        var release = runPipeline("Secret", "from the release");

        try (var ring = await(ringBuilder(service).withKeyFile(KEY_FILE_VERSION, release.keyFile()).withEphemeralKey(100).buildAsync())) {
            assertEquals("from the release", read(ring, release.configuration(), "Secret"));
            assertEquals(100, ring.getCurrentVersion());
            assertTrue(ring.createProtector("new").encrypt("value").startsWith("enc::v100::"));
        }
    }

    @Test
    void backgroundRefresh_AgainstTheRealKek_KeepsTheKeyInService() {
        try (var ring = await(ringBuilder(service).withKeyRefreshInterval(1).withEphemeralKey(1).buildAsync())) {
            var protector = ring.createProtector("refresh");
            var before = protector.encrypt("written before the refreshes");

            sleep(2500); // two background re-reveals through the native KEK

            var result = new char[64];
            assertEquals("written before the refreshes", new String(result, 0, protector.decrypt(before, result)));
            var after = protector.encrypt("written after");
            assertEquals("written after", new String(result, 0, protector.decrypt(after, result)));
        }
    }
}
