package io.github.runsecure.hkdfguard.dataencryptionkey;

import static io.github.runsecure.hkdfguard.dataencryptionkey.Futures.await;
import static io.github.runsecure.hkdfguard.dataencryptionkey.Futures.awaitFailure;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.InvalidKeyFileException;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.keywrapping.v1.NativeHkdfKeyWrapperV1Impl;
import io.github.runsecure.hkdfguard.keywrapping.v1.interop.NativeTestEnvironment;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A key ring reads its key files through the real native library's hkdfguard_open_file. Refusing a
 * plaintext key file needs only the installed Windows library; building from a real wrapped key
 * needs the service NativeTestEnvironment.assumeService chooses - HKDFGUARD_TEST_SERVICE, or on
 * Windows and macOS the provisioned NativeTestEnvironment.DEFAULT_SERVICE_NAME. Reported as skipped
 * where those are missing. Key files are written to NativeTestEnvironment.createTempDirectory: by
 * its real, long path on Windows, and on Linux a private directory the native library trusts.
 */
class NativeKeyFileRingTest {
    private Path directory;

    @BeforeEach
    void createDirectory() throws IOException {
        directory = NativeTestEnvironment.createTempDirectory("hkdfguard-keyfile-ring-");
    }

    @AfterEach
    void deleteDirectory() throws IOException {
        NativeTestEnvironment.deleteRecursively(directory);
    }

    private static KeyRingBuilder ringBuilder(String service) {
        return new KeyRingBuilder()
                .withKeyWrapper(new NativeHkdfKeyWrapperV1Impl(service))
                .withCryptoProviderFactory(new AesGcmCryptoProviderFactoryImpl())
                .withKeyRefreshInterval(60);
    }

    @Test
    void aKeyRing_BuiltFromAKeyFile_ReadsItThroughTheNativeLibrary() throws Exception {
        var service = NativeTestEnvironment.assumeService();
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
        NativeTestEnvironment.assumeWindowsLibraryInstalled();
        var dek = new byte[32];
        new SecureRandom().nextBytes(dek);
        var path = Files.write(directory.resolve("plaintext.bin"), dek);

        // Any valid service name: the file is refused before any KEK is involved.
        var thrown = awaitFailure(InvalidKeyFileException.class, ringBuilder("hkdfguard.keyfile.reader").withKeyFile(1, path).buildAsync());

        assertTrue(thrown.getMessage().contains("status -37"), thrown.getMessage());
    }
}
