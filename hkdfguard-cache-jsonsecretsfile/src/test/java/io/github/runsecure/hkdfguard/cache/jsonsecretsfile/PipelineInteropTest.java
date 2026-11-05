package io.github.runsecure.hkdfguard.cache.jsonsecretsfile;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import io.github.runsecure.hkdfguard.cache.filepersecret.FilePerSecretCacheImpl;
import io.github.runsecure.hkdfguard.cache.jsonsecretsfile.JsonSecretsFileReadOnlyCacheImplTest.FixedKeyWrapper;
import io.github.runsecure.hkdfguard.cache.jsonsecretsfile.JsonSecretsFileReadOnlyCacheImplTest.InMemoryWriter;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderImpl;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmPipelineDataProtectorImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.DataEncryptionKeyImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The pipeline's output read back by the runtime caches, end to end: the JSON file by this module's
 * cache, and the tar archive unpacked by the platform's real tar - GNU tar on Linux, bsdtar on
 * macOS and Windows (tar.exe) - into a folder FilePerSecretCacheImpl reads. The tar test is skipped
 * where no tar is installed.
 */
class PipelineInteropTest {
    private static final Map<String, String> SECRETS = secrets();

    private TrustedTempDirectory dir;
    private AesGcmPipelineDataProtectorImpl protector;
    private InMemoryWriter writer;
    private KeyRingImpl ring;

    private static Map<String, String> secrets() {
        var secrets = new LinkedHashMap<String, String>();
        secrets.put("db-login__password", "p\u00e4ssw\u00f6rd");
        secrets.put("api-key", "key+with/slashes");
        secrets.put("Zeta", "upper case, first in ordinal order");
        secrets.put("alpha.v2", "\u65e5\u672c\u8a9e \uD83D\uDD11");
        secrets.put("n".repeat(120), "a name longer than ustar's 100 bytes");
        return secrets;
    }

    @BeforeEach
    void pull() throws Exception {
        dir = new TrustedTempDirectory();
        protector = new AesGcmPipelineDataProtectorImpl(new DefaultFormatProviderImpl(), 1);
        writer = new InMemoryWriter(protector, SECRETS);
        writer.pullSecretsAsync().get(10, TimeUnit.SECONDS);

        // What the application holds once the pipeline's key has been wrapped and unwrapped: the
        // key as writeDekAsync hands it to the wrap tool.
        var dek = new ByteArrayOutputStream();
        protector.writeDekAsync(dek).get(10, TimeUnit.SECONDS);
        var key = Base64.getDecoder().decode(dek.toByteArray());
        ring = new KeyRingImpl(new DefaultFormatProviderImpl());
        ring.add(1, new DataEncryptionKeyImpl(AesGcmCryptoProviderImpl.createAsync(new FixedKeyWrapper(key),
                "wrapped".getBytes(StandardCharsets.UTF_8), 60).get(10, TimeUnit.SECONDS)));
    }

    @AfterEach
    void cleanUp() throws IOException {
        ring.close();
        writer.close();
        protector.close();
        dir.close();
    }

    private static void assertEachDecrypts(ProtectedReadOnlyCache cache) {
        for (var secret : SECRETS.entrySet()) {
            var result = new char[cache.findMaxDecryptedLength(secret.getKey()).orElseThrow()];
            assertEquals(secret.getValue(), new String(result, 0, cache.decrypt(secret.getKey(), result)), secret.getKey());
        }
    }

    @Test
    void theJsonFile_AndTheJsonStream_AreReadByTheJsonSecretsFileCache() throws Exception {
        var file = dir.path().resolve("secrets.json");
        writer.writeJsonSecrets(file);
        var streamed = dir.path().resolve("streamed.json");
        try (var stdin = Files.newOutputStream(streamed)) {
            writer.writeJsonSecretsAsync(stdin).get(10, TimeUnit.SECONDS);
        }

        assertArrayEquals(Files.readAllBytes(file), Files.readAllBytes(streamed));
        assertEachDecrypts(new JsonSecretsFileReadOnlyCacheImpl(file, dir.trust(), ring, new DefaultFormatProviderImpl()));
        assertEachDecrypts(new JsonSecretsFileReadOnlyCacheImpl(streamed, dir.trust(), ring, new DefaultFormatProviderImpl()));
    }

    @Test
    void theTarStream_UnpackedByTheRealTar_IsReadByTheFilePerSecretCache() throws Exception {
        var tar = tar();
        Assumptions.assumeTrue(tar != null, "No tar is installed.");
        var folder = Files.createDirectory(dir.path().resolve("unpacked"));

        // As a deployment runs it over ssh: the archive on tar's standard input.
        var process = new ProcessBuilder(tar, "-x", "--no-same-owner", "-f", "-", "-C", folder.toString())
                .redirectErrorStream(true)
                .start();
        try (var stdin = process.getOutputStream()) {
            writer.writeProtectedSecretFilesAsync(stdin).get(30, TimeUnit.SECONDS);
        }
        var output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertTrue(process.waitFor(30, TimeUnit.SECONDS), "tar didn't finish.");
        assertEquals(0, process.exitValue(), tar + ": " + output);

        try (var files = Files.list(folder)) {
            assertEquals(SECRETS.keySet().stream().sorted().toList(), files.map(f -> f.getFileName().toString()).sorted().toList());
        }
        for (var name : SECRETS.keySet())
            assertEquals(writer.getProtectedSecrets().get(name), Files.readString(folder.resolve(name)));
        assertEachDecrypts(new FilePerSecretCacheImpl(folder, dir.trust(), ring, new DefaultFormatProviderImpl()));
    }

    // The platform's tar: Windows' own tar.exe (bsdtar) by its full path, or the tar on the PATH.
    private static String tar() {
        if (System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows")) {
            var windowsTar = Path.of(System.getenv().getOrDefault("SystemRoot", "C:\\Windows"), "System32", "tar.exe");
            return Files.isRegularFile(windowsTar) ? windowsTar.toString() : null;
        }

        for (var folder : System.getenv().getOrDefault("PATH", "").split(File.pathSeparator)) {
            var candidate = Path.of(folder, "tar");
            if (Files.isExecutable(candidate))
                return candidate.toString();
        }
        return null;
    }
}
