package io.github.runsecure.hkdfguard.systemdcredentials;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.channels.NonReadableChannelException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class SystemdCredentialsTest {
    @TempDir
    Path folder;

    private final FakeSystemdCreds creds = new FakeSystemdCreds();

    private SystemdCredentials credentials(SystemdCredentialsOptions options) {
        return new SystemdCredentials(options, creds);
    }

    private SystemdCredentials credentials() {
        return credentials(null);
    }

    private String pathFor(String name) {
        return folder.resolve(name).toString();
    }

    private static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] bytes(SystemdCredential credential) {
        var value = credential.getValue();
        var bytes = new byte[value.remaining()];
        value.get(bytes);
        return bytes;
    }

    private static Throwable failure(CompletableFuture<?> future) {
        return assertThrows(CompletionException.class, future::join).getCause();
    }

    @Test
    void encrypt_WritesThePlaintextToStdin_AndTheFileIsSystemdCredsOwn() {
        var path = pathFor("tls-password.cred");

        credentials().encryptAsync("tls-password", "pässwörd", path).join();

        var run = creds.runs.get(0);
        assertEquals(1, creds.runs.size());
        assertEquals("/usr/bin/systemd-creds", run.executable());
        assertEquals(List.of("--name=tls-password", "--with-key=auto", "encrypt", "-", path), run.arguments());
        assertArrayEquals(utf8("pässwörd"), run.stdin());
        assertEquals(Duration.ofSeconds(30), run.timeout());
        assertTrue(Files.exists(Path.of(path)));
        // The text was encoded into an array of the call's own, zeroed once systemd-creds had run.
        assertTrue(ArrayUtility.isNullOrEmpty(run.stdinArray()));
    }

    @Test
    void encrypt_OfBytes_LeavesTheCallersArrayAlone() {
        var plaintext = utf8("s3cret");

        credentials().encryptAsync("item", plaintext, pathFor("item.cred")).join();

        assertArrayEquals(utf8("s3cret"), plaintext);
    }

    @ParameterizedTest
    @CsvSource({ "AUTO, auto", "HOST, host", "TPM2, tpm2", "HOST_AND_TPM2, host+tpm2" })
    void encrypt_UsesTheKeyAndScopeAsked(SystemdCredentialKey key, String argument) {
        var options = new SystemdCredentialsOptions();
        options.setKey(key);
        options.setUserScope(true);
        options.setExecutablePath("/usr/local/bin/systemd-creds");
        options.setTimeout(Duration.ofSeconds(5));

        credentials(options).encryptAsync("item", utf8("v"), pathFor("item.cred")).join();

        var run = creds.runs.get(0);
        assertEquals(List.of("--name=item", "--with-key=" + argument, "--user", "encrypt", "-", pathFor("item.cred")), run.arguments());
        assertEquals("/usr/local/bin/systemd-creds", run.executable());
        assertEquals(Duration.ofSeconds(5), run.timeout());
    }

    @Test
    void decrypt_ReadsTheValueFromStdout_IntoACredentialThatZeroesOnClose() {
        var credentials = credentials();
        credentials.encryptAsync("tls-password", "s3cret", pathFor("tls-password.cred")).join();

        var value = credentials.decryptAsync("tls-password", pathFor("tls-password.cred")).join();

        var run = creds.runs.get(creds.runs.size() - 1);
        assertEquals(List.of("--name=tls-password", "--newline=no", "decrypt", pathFor("tls-password.cred"), "-"), run.arguments());
        assertEquals(0, run.stdin().length);
        assertArrayEquals(utf8("s3cret"), bytes(value));
        assertEquals(6, value.getLength());
        var view = value.getValue();

        value.close();
        value.close();

        assertThrows(IllegalStateException.class, value::getValue);
        assertThrows(IllegalStateException.class, () -> value.copyTo(new byte[8]));
        var zeroed = new byte[view.remaining()];
        view.get(zeroed);
        assertTrue(ArrayUtility.isNullOrEmpty(zeroed));
    }

    @Test
    void decrypt_InUserScope_AsksForIt() {
        var options = new SystemdCredentialsOptions();
        options.setUserScope(true);
        var credentials = credentials(options);
        credentials.encryptAsync("item", utf8("v"), pathFor("item.cred")).join();

        credentials.decryptAsync("item", pathFor("item.cred")).join().close();

        assertEquals(List.of("--name=item", "--newline=no", "--user", "decrypt", pathFor("item.cred"), "-"), creds.runs.get(1).arguments());
    }

    @Test
    void aRenamedCredential_FailsToDecrypt_WithSystemdCredsMessage() {
        var credentials = credentials();
        credentials.encryptAsync("tls-password", utf8("s3cret"), pathFor("tls-password.cred")).join();

        var ex = failure(credentials.decryptAsync("db-password", pathFor("tls-password.cred")));

        assertInstanceOf(IllegalStateException.class, ex);
        assertEquals("systemd-creds decrypt failed with exit code 1: Embedded credential name 'tls-password' does not match filename 'db-password', refusing.",
                ex.getMessage());
        // The (empty) stdout of the failed run was zeroed all the same.
        assertThrows(IllegalStateException.class, () -> creds.outputs.get(creds.outputs.size() - 1).getValue());
    }

    @Test
    void aFailureWithoutAMessage_GivesTheExitCode() {
        creds.failExitCode = 243;
        creds.failError = " ";

        var ex = failure(credentials().encryptAsync("item", utf8("v"), pathFor("item.cred")));

        assertEquals("systemd-creds encrypt failed with exit code 243", ex.getMessage());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = { ".", "..", "-n", "a/b", "a b", "a\\b", "ä" })
    void anInvalidName_IsRefused_BeforeSystemdCredsRuns(String name) {
        assertFalse(SystemdCredentials.isValidName(name));
        assertThrows(IllegalArgumentException.class, () -> credentials().encryptAsync(name, utf8("v"), pathFor("x.cred")));
        assertThrows(IllegalArgumentException.class, () -> credentials().encryptAsync(name, "v", pathFor("x.cred")));
        assertThrows(IllegalArgumentException.class, () -> credentials().decryptAsync(name, pathFor("x.cred")));
        assertTrue(creds.runs.isEmpty());
    }

    @Test
    void aValidName_HoldsLettersDigitsDotsUnderscoresAndHyphens() {
        assertTrue(SystemdCredentials.isValidName("tls.pfx_password-2"));
        assertTrue(SystemdCredentials.isValidName("a".repeat(SystemdCredentials.MAX_NAME_LENGTH)));
        assertFalse(SystemdCredentials.isValidName("a".repeat(SystemdCredentials.MAX_NAME_LENGTH + 1)));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = { "relative/item.cred" })
    void aRelativePath_IsRefused(String path) {
        assertThrows(IllegalArgumentException.class, () -> credentials().encryptAsync("item", utf8("v"), path));
        assertThrows(IllegalArgumentException.class, () -> credentials().decryptAsync("item", path));
        assertTrue(creds.runs.isEmpty());
    }

    @Test
    void thePlaintext_IsRequired() {
        assertThrows(NullPointerException.class, () -> credentials().encryptAsync("item", (byte[]) null, pathFor("x.cred")));
        assertThrows(NullPointerException.class, () -> credentials().encryptAsync("item", (CharSequence) null, pathFor("x.cred")));
    }

    @Test
    void theOptions_AreChecked() {
        var relative = new SystemdCredentialsOptions();
        relative.setExecutablePath("systemd-creds");
        assertThrows(IllegalArgumentException.class, () -> credentials(relative));
        var empty = new SystemdCredentialsOptions();
        empty.setExecutablePath("");
        assertThrows(IllegalArgumentException.class, () -> credentials(empty));
        var noKey = new SystemdCredentialsOptions();
        noKey.setKey(null);
        assertThrows(IllegalArgumentException.class, () -> credentials(noKey));
        var zero = new SystemdCredentialsOptions();
        zero.setTimeout(Duration.ZERO);
        assertThrows(IllegalArgumentException.class, () -> credentials(zero));
        var negative = new SystemdCredentialsOptions();
        negative.setTimeout(Duration.ofSeconds(-1));
        assertThrows(IllegalArgumentException.class, () -> credentials(negative));
    }

    @Test
    void thePublicConstructor_IsLinuxOnly() {
        SystemdCredentials.requireLinux(true);
        assertThrows(UnsupportedOperationException.class, () -> SystemdCredentials.requireLinux(false));

        if (System.getProperty("os.name").startsWith("Linux"))
            new SystemdCredentials();
        else
            assertThrows(UnsupportedOperationException.class, SystemdCredentials::new);
    }

    @Test
    void aLoadedCredential_IsReadFromTheCredentialsDirectory() throws IOException {
        Files.writeString(folder.resolve("tls-password"), "s3cret");

        try (var value = SystemdCredentials.readLoadedCredential("tls-password", folder.toString())) {
            assertArrayEquals(utf8("s3cret"), bytes(value));
        }
        assertNull(SystemdCredentials.readLoadedCredential("absent", folder.toString()));
        assertThrows(IllegalArgumentException.class, () -> SystemdCredentials.readLoadedCredential("../etc", folder.toString()));
    }

    @Test
    void anEmptyLoadedCredential_IsAnEmptyValue() throws IOException {
        Files.write(folder.resolve("empty"), new byte[0]);

        try (var value = SystemdCredentials.readLoadedCredential("empty", folder.toString())) {
            assertEquals(0, value.getLength());
        }
    }

    @Test
    void withoutACredentialsDirectory_NothingIsLoaded() {
        Assumptions.assumeTrue(System.getenv(SystemdCredentials.CREDENTIALS_DIRECTORY_VARIABLE) == null,
                "Runs only where " + SystemdCredentials.CREDENTIALS_DIRECTORY_VARIABLE + " is unset: Java can't unset it.");

        assertNull(SystemdCredentials.readLoadedCredential("tls-password"));
        assertNull(SystemdCredentials.loadedCredentialPath("tls-password", null));
    }

    // Records every array read into, as SystemdCredential.read is handed them.
    private static final class RecordingStream extends InputStream {
        private final ByteArrayInputStream inner;
        private final int chunk;
        final List<byte[]> arrays = new ArrayList<>();
        final List<Integer> asked = new ArrayList<>();

        RecordingStream(byte[] contents, int chunk) {
            this.inner = new ByteArrayInputStream(contents);
            this.chunk = chunk;
        }

        @Override
        public int read() {
            throw new UnsupportedOperationException();
        }

        @Override
        public int read(byte[] b, int off, int len) {
            if (arrays.isEmpty() || arrays.get(arrays.size() - 1) != b)
                arrays.add(b);
            asked.add(len);
            return inner.read(b, off, Math.min(len, chunk));
        }
    }

    @Test
    void aValue_GrowsAsItIsRead_UpToSystemdsLimit_ZeroingEveryArrayItOutgrew() {
        var large = new byte[SystemdCredential.MAX_LENGTH];
        new SecureRandom().nextBytes(large);
        var stream = new RecordingStream(large, 5000);

        try (var value = SystemdCredential.read(stream)) {
            assertArrayEquals(large, bytes(value));
            assertTrue(stream.arrays.size() > 5, "it grew " + stream.arrays.size() + " times");
            for (var outgrown : stream.arrays.subList(0, stream.arrays.size() - 1))
                assertTrue(ArrayUtility.isNullOrEmpty(outgrown));
            // Every read asked for enough to bypass a BufferedInputStream's 8 KiB buffer.
            assertTrue(stream.asked.stream().allMatch(n -> n >= SystemdCredential.MIN_READ), stream.asked.toString());
        }

        var over = new RecordingStream(new byte[SystemdCredential.MAX_LENGTH + 1], 1 << 20);
        assertThrows(InvalidSecretDataException.class, () -> SystemdCredential.read(over));
        for (var array : over.arrays)
            assertTrue(ArrayUtility.isNullOrEmpty(array));
    }

    @Test
    void aValue_IsDecodedAsUtf8_OrRefusedWhenTooLong() {
        try (var value = SystemdCredential.read(new ByteArrayInputStream(utf8("pässwörd")))) {
            var chars = new char[8];
            assertEquals(8, value.decodeTo(chars));
            assertEquals("pässwörd", new String(chars));
            var small = new char[3];
            assertThrows(IllegalArgumentException.class, () -> value.decodeTo(small));
            assertTrue(ArrayUtility.isNullOrEmpty(small));
            assertThrows(IllegalArgumentException.class, () -> value.copyTo(new byte[3]));
        }
    }

    @Test
    void aFileOverSystemdsLimit_IsRefused() throws IOException {
        try (var file = FileChannel.open(folder.resolve("big"), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)) {
            file.write(java.nio.ByteBuffer.wrap(new byte[1]), SystemdCredential.MAX_LENGTH);
        }

        assertThrows(InvalidSecretDataException.class, () -> SystemdCredentials.readLoadedCredential("big", folder.toString()));
    }

    @Test
    void aFileThatCantBeRead_IsRefused() throws IOException {
        Files.writeString(folder.resolve("write-only"), "s3cret");
        try (var channel = FileChannel.open(folder.resolve("write-only"), StandardOpenOption.WRITE)) {
            assertThrows(NonReadableChannelException.class, () -> SystemdCredential.readFile(channel));
        }
        assertThrows(UncheckedIOException.class, () -> SystemdCredential.readFile(folder.resolve("absent")));
    }

    @Test
    void aFailingRead_ZeroesWhatItHad() {
        var arrays = new ArrayList<byte[]>();
        var stream = new InputStream() {
            private boolean readOnce;

            @Override
            public int read() {
                throw new UnsupportedOperationException();
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                arrays.add(b);
                if (readOnce)
                    throw new IOException("lost");
                readOnce = true;
                var partial = utf8("partial");
                System.arraycopy(partial, 0, b, off, partial.length);
                return partial.length;
            }
        };

        var ex = assertThrows(UncheckedIOException.class, () -> SystemdCredential.read(stream));

        assertEquals("lost", ex.getCause().getMessage());
        assertTrue(ArrayUtility.isNullOrEmpty(arrays.get(0)));
    }

    @Test
    void cancellingARun_InterruptsIt() throws Exception {
        var started = new CountDownLatch(1);
        var interrupted = new AtomicBoolean();
        creds.before = () -> {
            started.countDown();
            try {
                Thread.sleep(60_000);
            } catch (InterruptedException e) {
                interrupted.set(true);
                throw e;
            }
        };

        var decrypting = credentials().decryptAsync("item", pathFor("item.cred"));
        assertTrue(started.await(10, TimeUnit.SECONDS));
        assertTrue(decrypting.cancel(true));

        assertThrows(CancellationException.class, decrypting::join);
        for (var i = 0; i < 100 && !interrupted.get(); i++)
            Thread.sleep(50);
        assertTrue(interrupted.get());

        // The same for an encryption, whose future is a step removed from the run.
        var encryptStarted = new CountDownLatch(1);
        var encryptInterrupted = new AtomicBoolean();
        creds.before = () -> {
            encryptStarted.countDown();
            try {
                Thread.sleep(60_000);
            } catch (InterruptedException e) {
                encryptInterrupted.set(true);
                throw e;
            }
        };
        var encrypting = credentials().encryptAsync("item", "v", pathFor("item.cred"));
        assertTrue(encryptStarted.await(10, TimeUnit.SECONDS));
        encrypting.cancel(true);
        for (var i = 0; i < 100 && !encryptInterrupted.get(); i++)
            Thread.sleep(50);
        assertTrue(encryptInterrupted.get());
        // Its plaintext was still zeroed once the run ended.
        for (var i = 0; i < 100 && !ArrayUtility.isNullOrEmpty(creds.runs.get(1).stdinArray()); i++)
            Thread.sleep(50);
        assertTrue(ArrayUtility.isNullOrEmpty(creds.runs.get(1).stdinArray()));
    }

    @Test
    void aValueThatArrivesAfterACancel_IsZeroed() throws Exception {
        var credentials = credentials();
        credentials.encryptAsync("item", utf8("s3cret"), pathFor("item.cred")).join();
        var release = new CountDownLatch(1);
        var started = new CountDownLatch(1);
        creds.before = () -> {
            started.countDown();
            // Ignores the interrupt, as a run that had already finished would.
            while (true) {
                try {
                    if (release.await(10, TimeUnit.SECONDS))
                        return;
                } catch (InterruptedException e) {
                    // keep waiting
                }
            }
        };

        var decrypting = credentials.decryptAsync("item", pathFor("item.cred"));
        assertTrue(started.await(10, TimeUnit.SECONDS));
        decrypting.cancel(true);
        release.countDown();

        for (var i = 0; i < 100 && creds.outputs.size() < 2; i++)
            Thread.sleep(50);
        var late = creds.outputs.get(creds.outputs.size() - 1);
        for (var i = 0; i < 100; i++) {
            try {
                late.getValue();
                Thread.sleep(50);
            } catch (IllegalStateException closed) {
                return;
            }
        }
        throw new AssertionError("The value that arrived after the cancel wasn't zeroed.");
    }

    @Test
    void aTimeout_FailsTheFuture() {
        creds.before = () -> {
            throw new TimeoutException("systemd-creds didn't finish within PT30S.");
        };

        var ex = failure(credentials().decryptAsync("item", pathFor("item.cred")));

        assertInstanceOf(TimeoutException.class, ex);
        assertEquals("systemd-creds didn't finish within PT30S.", ex.getMessage());
    }
}
