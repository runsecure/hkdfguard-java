package io.github.runsecure.hkdfguard.dataencryptionkey;

import static io.github.runsecure.hkdfguard.dataencryptionkey.Futures.await;
import static io.github.runsecure.hkdfguard.dataencryptionkey.Futures.awaitFailure;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.InvalidKeyFileException;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.keywrapping.v1.NativeHkdfKeyWrapperV1Impl;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A key ring reads its key files through the real native library's hkdfguard_open_file. Refusing a
 * plaintext key file needs only the installed Windows library; building from a real wrapped key
 * needs HKDFGUARD_TEST_SERVICE, or on Windows the provisioned test KEK
 * com.hkdfguard.integration.test.221. Reported as skipped where those are missing.
 */
class NativeKeyFileRingTest {
    private static final String WINDOWS_TEST_SERVICE = "com.hkdfguard.integration.test.221";

    private Path directory;

    @BeforeEach
    void createDirectory() throws IOException {
        // By its real, long path: hkdfguard_open_file refuses an 8.3 short name or a link anywhere
        // in a path, and the temp folder can be handed out in short form (C:\Users\RUNNER~1\...).
        directory = Files.createTempDirectory("hkdfguard-keyfile-ring-").toRealPath();
    }

    @AfterEach
    void deleteDirectory() throws IOException {
        try (var paths = Files.walk(directory)) {
            for (var path : paths.sorted(Comparator.reverseOrder()).toList())
                Files.deleteIfExists(path);
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows");
    }

    private static void assumeWindowsLibraryInstalled() {
        Assumptions.assumeTrue(isWindows(), "Windows only.");
        var programFiles = System.getenv("ProgramFiles");
        Assumptions.assumeTrue(programFiles != null && Files.isRegularFile(Path.of(programFiles, "HkdfGuard", "v1", "HkdfGuard.dll")),
                "The Windows native KMS library is not installed.");
    }

    /** The provisioned service, skipping the calling test when there is none. */
    private static String assumeService() {
        var explicit = System.getenv("HKDFGUARD_TEST_SERVICE");
        if (explicit != null && !explicit.isEmpty())
            return explicit;

        assumeWindowsLibraryInstalled();
        try {
            new NativeHkdfKeyWrapperV1Impl(WINDOWS_TEST_SERVICE).generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]).get();
        } catch (ExecutionException | InterruptedException e) {
            var message = String.valueOf(e.getCause() == null ? e : e.getCause().getMessage());
            // Not provisioned (-17) or not permitted (-18): skip. Anything else is a real failure.
            Assumptions.assumeFalse(message.contains("status -17") || message.contains("status -18"),
                    "The Windows test KEK is unavailable: " + message);
        }
        return WINDOWS_TEST_SERVICE;
    }

    private static KeyRingBuilder ringBuilder(String service) {
        return new KeyRingBuilder()
                .withKeyWrapper(new NativeHkdfKeyWrapperV1Impl(service))
                .withCryptoProviderFactory(new AesGcmCryptoProviderFactoryImpl())
                .withKeyRefreshInterval(60);
    }

    @Test
    void aKeyRing_BuiltFromAKeyFile_ReadsItThroughTheNativeLibrary() throws Exception {
        var service = assumeService();
        var dek = new byte[32];
        new SecureRandom().nextBytes(dek);
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = new NativeHkdfKeyWrapperV1Impl(service).wrapAsync(dek, wrapped).get();
        var path = Files.write(directory.resolve("wrapped-dek-v4.bin"), Arrays.copyOf(wrapped, length));

        try (var ring = await(ringBuilder(service).withKeyFile(4, path).buildAsync())) {
            assertEquals(4, ring.getCurrentVersion());
        }
    }

    @Test
    void aKeyRing_RefusesToBuildFromAPlaintextKeyFile() throws IOException {
        assumeWindowsLibraryInstalled();
        var dek = new byte[32];
        new SecureRandom().nextBytes(dek);
        var path = Files.write(directory.resolve("plaintext.bin"), dek);

        // Any valid service name: the file is refused before any KEK is involved.
        var thrown = awaitFailure(InvalidKeyFileException.class, ringBuilder("hkdfguard.keyfile.reader").withKeyFile(1, path).buildAsync());

        assertTrue(thrown.getMessage().contains("status -37"), thrown.getMessage());
    }
}
