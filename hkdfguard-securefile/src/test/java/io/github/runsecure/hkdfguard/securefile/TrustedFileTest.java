package io.github.runsecure.hkdfguard.securefile;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.github.runsecure.hkdfguard.testsupport.WindowsTempDirectory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

class TrustedFileTest {
    private static final int LIMIT = 64;

    private static final SecureRandom RANDOM = new SecureRandom();

    private static byte[] random(int length) {
        var bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static byte[] readContents(InputStream stream) throws IOException {
        return TrustedFile.readContents(stream, "secret.enc", LIMIT);
    }

    private static int readContentsLength(InputStream stream) throws IOException {
        return TrustedFile.readContents(stream, "secret.enc", LIMIT, ByteBuffer::remaining);
    }

    private static byte[] toArray(ByteBuffer contents) {
        var copy = new byte[contents.remaining()];
        contents.get(copy);
        return copy;
    }

    /** The failure a completed future holds; fails the test if it succeeded. */
    private static <E extends Throwable> E failure(Class<E> type, CompletableFuture<?> future) {
        try {
            future.get(10, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            return assertInstanceOf(type, e.getCause());
        } catch (InterruptedException | TimeoutException e) {
            throw new AssertionError("The future did not complete.", e);
        }
        return fail("Expected the read to fail with " + type.getSimpleName() + ".");
    }

    private static <T> T await(CompletableFuture<T> future) throws Exception {
        try {
            return future.get(10, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            throw e.getCause() instanceof Exception cause ? cause : e;
        }
    }

    // --- Contents ----------------------------------------------------------------------------

    @Test
    void readContents_ReturnsTheContentsExactly() throws IOException {
        var contents = random(40);

        assertArrayEquals(contents, readContents(new ByteArrayInputStream(contents)));
    }

    @Test
    void readContents_ExactlyTheLimit_IsAccepted() throws IOException {
        var contents = random(LIMIT);

        assertArrayEquals(contents, readContents(new ByteArrayInputStream(contents)));
        assertEquals(LIMIT, readContentsLength(new ByteArrayInputStream(contents)));
    }

    @Test
    void readContents_AnEmptyFile_IsReturnedEmpty() throws IOException {
        assertEquals(0, readContents(new ByteArrayInputStream(new byte[0])).length);
        assertEquals(0, readContentsLength(new ByteArrayInputStream(new byte[0])));
    }

    @Test
    void readContents_OverTheLimit_IsRefused_ReadingOnlyOneBytePast() {
        var stream = new CountingInputStream(new byte[LIMIT * 4]);
        var ex = assertThrows(FileTooLargeException.class, () -> readContents(stream));
        assertTrue(ex.getMessage().contains("larger than " + LIMIT + " bytes"), ex.getMessage());
        assertEquals(LIMIT + 1, stream.position);

        var parsed = new AtomicBoolean();
        var second = new CountingInputStream(new byte[LIMIT * 4]);
        assertThrows(FileTooLargeException.class, () -> TrustedFile.readContents(second, "secret.enc", LIMIT, contents -> {
            parsed.set(true);
            return null;
        }));
        assertFalse(parsed.get());
        assertEquals(LIMIT + 1, second.position);
    }

    @Test
    void readContents_AppliesNoKeyFileRules() throws IOException {
        // TrustedKeyFile refuses exactly 32 bytes as a probable plaintext key; TrustedFile leaves
        // the contents to its caller.
        var contents = random(32);

        assertArrayEquals(contents, readContents(new ByteArrayInputStream(contents)));
    }

    @Test
    void readContents_ParserSeesTheContents_AndItsResultIsReturned() throws IOException {
        var contents = random(40);

        assertArrayEquals(contents, TrustedFile.readContents(new ByteArrayInputStream(contents), "secret.enc", LIMIT, TrustedFileTest::toArray));
    }

    @Test
    void readContents_TheParserSeesAReadOnlyView_ZeroedOnceItReturns() throws IOException {
        var contents = random(40);
        contents[0] = 1;
        var seen = new AtomicReference<ByteBuffer>();

        TrustedFile.readContents(new ByteArrayInputStream(contents), "secret.enc", LIMIT, view -> {
            seen.set(view);
            return null;
        });

        var view = seen.get();
        assertTrue(view.isReadOnly());
        assertEquals(contents.length, view.remaining());
        for (var i = 0; i < view.remaining(); i++)
            assertEquals(0, view.get(i), "byte " + i + " was not zeroed");
    }

    @Test
    void readContents_AParserException_Propagates() {
        var thrown = new IllegalStateException("parse");

        var ex = assertThrows(IllegalStateException.class, () -> TrustedFile.readContents(new ByteArrayInputStream(new byte[] {1, 2, 3}), "secret.enc",
                LIMIT, contents -> {
                    throw thrown;
                }));
        assertSame(thrown, ex);
    }

    @Test
    void readAsync_InvalidArguments_AreRefusedBeforeAnythingIsOpened() {
        var trust = KeyFileTrust.ADMINISTRATORS_ONLY;
        var path = Path.of("secret.enc");

        assertThrows(IllegalArgumentException.class, () -> TrustedFile.readAsync(Path.of(""), trust, LIMIT));
        assertThrows(NullPointerException.class, () -> TrustedFile.readAsync(null, trust, LIMIT));
        assertThrows(NullPointerException.class, () -> TrustedFile.readAsync(path, null, LIMIT));
        assertThrows(IllegalArgumentException.class, () -> TrustedFile.readAsync(path, trust, 0));
        assertThrows(IllegalArgumentException.class, () -> TrustedFile.readAsync(path, trust, TrustedFile.MAX_ARRAY_LENGTH));
        assertThrows(NullPointerException.class, () -> TrustedFile.readAsync(path, trust, LIMIT, null));
        assertThrows(IllegalArgumentException.class, () -> TrustedFile.readAsync(path, trust, -1, ByteBuffer::remaining));
    }

    // --- Windows, real files -----------------------------------------------------------------

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readAsync_Windows_AFileInTheUsersOwnFolder_IsRefusedByDefault() throws IOException {
        try (var dir = new WindowsTempDirectory()) {
            var path = dir.write("secret.enc", random(40));

            var ex = failure(AccessDeniedException.class, TrustedFile.readAsync(path, KeyFileTrust.ADMINISTRATORS_ONLY, LIMIT));
            assertTrue(ex.getMessage().contains("not trusted"));
            failure(AccessDeniedException.class, TrustedFile.readAsync(path, KeyFileTrust.ADMINISTRATORS_ONLY, LIMIT, ByteBuffer::remaining));
        }
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readAsync_Windows_WithTheUserTrusted_ReadsTheFileThroughEitherOverload() throws Exception {
        try (var dir = new WindowsTempDirectory()) {
            var contents = random(40);
            var path = dir.write("secret.enc", contents);

            assertArrayEquals(contents, await(TrustedFile.readAsync(path, trustCurrentWindowsUser(), LIMIT)));
            assertArrayEquals(contents, await(TrustedFile.readAsync(path, trustCurrentWindowsUser(), LIMIT, TrustedFileTest::toArray)));
        }
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readAsync_Windows_AnEmptyFile_IsRead() throws Exception {
        try (var dir = new WindowsTempDirectory()) {
            var path = dir.write("secret.enc", new byte[0]);

            assertEquals(0, await(TrustedFile.readAsync(path, trustCurrentWindowsUser(), LIMIT)).length);
        }
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readAsync_Windows_AFileOverTheLimit_IsRefused() throws IOException {
        try (var dir = new WindowsTempDirectory()) {
            var path = dir.write("secret.enc", new byte[LIMIT + 1]);

            failure(FileTooLargeException.class, TrustedFile.readAsync(path, trustCurrentWindowsUser(), LIMIT));
        }
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readAsync_Windows_AMissingFile_IsNotFound() throws IOException {
        try (var dir = new WindowsTempDirectory()) {
            failure(NoSuchFileException.class, TrustedFile.readAsync(dir.path().resolve("missing.enc"), trustCurrentWindowsUser(), LIMIT));
            failure(NoSuchFileException.class, TrustedFile.readAsync(dir.path().resolve("missing").resolve("secret.enc"), trustCurrentWindowsUser(), LIMIT));
        }
    }

    // --- Linux and macOS, real files ---------------------------------------------------------

    @Test
    @EnabledOnOs(value = {OS.LINUX, OS.MAC}, disabledReason = "Linux and macOS only.")
    void readAsync_Unix_ARootOwnedSystemFile_IsReadThroughEitherOverload() throws Exception {
        // /etc/hosts: root-owned all the way up (through macOS's root-owned /etc link), and any
        // contents at all are accepted.
        var expected = Files.readAllBytes(Path.of("/etc/hosts"));

        assertArrayEquals(expected, await(TrustedFile.readAsync(Path.of("/etc/hosts"), KeyFileTrust.ADMINISTRATORS_ONLY, 1024 * 1024)));
        assertEquals(expected.length, await(TrustedFile.readAsync(Path.of("/etc/hosts"), KeyFileTrust.ADMINISTRATORS_ONLY, 1024 * 1024,
                ByteBuffer::remaining)));
    }

    @Test
    @EnabledOnOs(value = {OS.LINUX, OS.MAC}, disabledReason = "Linux and macOS only.")
    void readAsync_Unix_AFileUnderTheSharedTempDirectory_IsRefused() throws IOException {
        // /tmp is writable by everyone (sticky or not), so nothing beneath it is trusted.
        var dir = Files.createDirectory(Path.of("/tmp", "hkdfguard-" + UUID.randomUUID()));
        try {
            var path = Files.write(dir.resolve("secret.enc"), random(40));

            var ex = failure(AccessDeniedException.class, TrustedFile.readAsync(path, KeyFileTrust.ADMINISTRATORS_ONLY, LIMIT));
            assertTrue(ex.getMessage().contains("not trusted"));
        } finally {
            Files.deleteIfExists(dir.resolve("secret.enc"));
            Files.deleteIfExists(dir);
        }
    }

    @Test
    @EnabledOnOs(value = {OS.LINUX, OS.MAC}, disabledReason = "Linux and macOS only.")
    void readAsync_Unix_AMissingFile_IsNotFound() {
        failure(NoSuchFileException.class,
                TrustedFile.readAsync(Path.of("/hkdfguard-missing-" + UUID.randomUUID() + ".enc"), KeyFileTrust.ADMINISTRATORS_ONLY, LIMIT));
    }

    /** Counts what is read from it, as .NET's MemoryStream.Position would. */
    private static final class CountingInputStream extends InputStream {
        private final byte[] data;
        int position;

        CountingInputStream(byte[] data) {
            this.data = data;
        }

        @Override
        public int read() {
            return position < data.length ? data[position++] & 0xFF : -1;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) {
            if (position >= data.length)
                return -1;
            var count = Math.min(length, data.length - position);
            System.arraycopy(data, position, buffer, offset, count);
            position += count;
            return count;
        }
    }

    /** Trusts the account running the tests, which owns, and may modify, its own temp folder. */
    private static KeyFileTrust trustCurrentWindowsUser() {
        return KeyFileTrust.ADMINISTRATORS_ONLY.withWindowsPrincipals(WindowsTempDirectory.currentUserSid());
    }
}
