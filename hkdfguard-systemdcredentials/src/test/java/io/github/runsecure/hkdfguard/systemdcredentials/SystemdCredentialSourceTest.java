package io.github.runsecure.hkdfguard.systemdcredentials;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class SystemdCredentialSourceTest {
    @TempDir
    Path folder;

    private Path loaded;
    private final FakeSystemdCreds creds = new FakeSystemdCreds();
    private SystemdCredentials credentials;

    @BeforeEach
    void setUp() throws IOException {
        loaded = Files.createDirectory(folder.resolve("loaded"));
        credentials = new SystemdCredentials(null, creds);
    }

    private String encryptedFile(String name, String value) {
        var path = folder.resolve(name + ".cred").toString();
        credentials.encryptAsync(name, value, path).join();
        return path;
    }

    private long decryptRuns() {
        return creds.runs.stream().filter(r -> r.arguments().contains("decrypt")).count();
    }

    @Test
    void anEncryptedFile_IsDecryptedBySystemdCreds_ForEveryLookup() {
        var source = new SystemdCredentialSource(credentials, Map.of("tls-password", encryptedFile("tls-password", "pässwörd")), loaded.toString());

        var max = source.findMaxDecryptedLength("tls-password").orElseThrow();
        var chars = new char[max];
        assertEquals("pässwörd", new String(chars, 0, source.decrypt("tls-password", chars)));
        var bytes = new byte[max];
        assertArrayEquals("pässwörd".getBytes(StandardCharsets.UTF_8), Arrays.copyOf(bytes, source.decrypt("tls-password", bytes)));
        assertEquals("pässwörd", new String(chars, 0, source.decryptAsync("tls-password", chars).join()));
        assertEquals(10, source.decryptAsync("tls-password", bytes).join());
        assertEquals(OptionalInt.of(max), source.findMaxDecryptedLengthAsync("tls-password").join());

        // Every value read is a systemd-creds run; a length isn't.
        assertEquals(4, decryptRuns());
        // And every value it read was zeroed once copied out.
        for (var output : creds.outputs)
            assertThrows(IllegalStateException.class, output::getValue);
    }

    @Test
    void aLoadedCredential_IsReadFirst_WithoutSystemdCreds() throws IOException {
        Files.writeString(loaded.resolve("tls-password"), "from-systemd");
        var source = new SystemdCredentialSource(credentials, Map.of("tls-password", encryptedFile("tls-password", "from-file")), loaded.toString());

        var chars = new char[64];
        assertEquals("from-systemd", new String(chars, 0, source.decrypt("tls-password", chars)));
        assertEquals("from-systemd", new String(chars, 0, source.decryptAsync("tls-password", chars).join()));
        assertEquals(0, decryptRuns());
    }

    @Test
    void onlyLoadedCredentials_NeedNoSystemdCredentials() throws IOException {
        Files.writeString(loaded.resolve("tls-password"), "s3cret");
        var source = new SystemdCredentialSource(null, null, loaded.toString());

        var max = source.findMaxDecryptedLength("tls-password").orElseThrow();
        assertEquals(6, source.decrypt("tls-password", new byte[max]));
        new SystemdCredentialSource();
    }

    @Test
    void aMissingOrInvalidName_IsReportedMissing() {
        var source = new SystemdCredentialSource(credentials, Map.of("gone", folder.resolve("gone.cred").toString()), loaded.toString());

        for (var name : List.of("absent", "gone", "../etc")) {
            assertEquals(OptionalInt.empty(), source.findMaxDecryptedLength(name));
            assertEquals(0, source.decrypt(name, new char[8]));
            assertEquals(0, source.decrypt(name, new byte[8]));
            assertEquals(0, source.decryptAsync(name, new char[8]).join());
            assertEquals(0, source.decryptAsync(name, new byte[8]).join());
            assertEquals(OptionalInt.empty(), source.findMaxDecryptedLengthAsync(name).join());
        }

        assertThrows(NullPointerException.class, () -> source.decrypt(null, new char[8]));
        // decryptAsync reports every failure through its future, a null name included.
        var ex = assertThrows(CompletionException.class, () -> source.decryptAsync(null, new char[8]).join());
        assertInstanceOf(NullPointerException.class, ex.getCause());
    }

    @Test
    void aResultTooSmall_IsRefused() {
        var source = new SystemdCredentialSource(credentials, Map.of("item", encryptedFile("item", "s3cret")), null);

        var chars = new char[3];
        assertThrows(IllegalArgumentException.class, () -> source.decrypt("item", chars));
        assertTrue(ArrayUtility.isNullOrEmpty(chars));
        assertThrows(IllegalArgumentException.class, () -> source.decrypt("item", new byte[3]));
        var ex = assertThrows(CompletionException.class, () -> source.decryptAsync("item", new byte[3]).join());
        assertInstanceOf(IllegalArgumentException.class, ex.getCause());
    }

    @Test
    void aFailedDecryption_IsReported() {
        var source = new SystemdCredentialSource(credentials, Map.of("item", encryptedFile("item", "s3cret")), null);
        creds.failExitCode = 1;
        creds.failError = "No access to the TPM.";

        var sync = assertThrows(IllegalStateException.class, () -> source.decrypt("item", new byte[16]));
        assertEquals("systemd-creds decrypt failed with exit code 1: No access to the TPM.", sync.getMessage());
        var async = assertThrows(CompletionException.class, () -> source.decryptAsync("item", new byte[16]).join());
        assertEquals(sync.getMessage(), async.getCause().getMessage());
    }

    @Test
    void cancellingAnAsyncLookup_CancelsTheRun() throws Exception {
        var source = new SystemdCredentialSource(credentials, Map.of("item", encryptedFile("item", "s3cret")), null);
        var started = new CountDownLatch(1);
        var interrupted = new CountDownLatch(1);
        creds.before = () -> {
            started.countDown();
            try {
                Thread.sleep(60_000);
            } catch (InterruptedException e) {
                interrupted.countDown();
                throw e;
            }
        };

        var lookup = source.decryptAsync("item", new byte[16]);
        assertTrue(started.await(10, TimeUnit.SECONDS));
        lookup.cancel(true);

        assertTrue(interrupted.await(10, TimeUnit.SECONDS));
    }

    @Test
    void theEncryptedFiles_AreChecked() {
        var somewhere = folder.resolve("x").toString();
        assertThrows(IllegalArgumentException.class, () -> new SystemdCredentialSource(credentials, Map.of("a b", somewhere), null));
        assertThrows(IllegalArgumentException.class, () -> new SystemdCredentialSource(credentials, Map.of("item", "relative.cred"), null));
        assertThrows(IllegalArgumentException.class, () -> new SystemdCredentialSource(credentials, Map.of("item", ""), null));
        assertThrows(IllegalArgumentException.class, () -> new SystemdCredentialSource(null, Map.of("item", somewhere), null));
    }
}
