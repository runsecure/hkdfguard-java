package io.github.runsecure.hkdfguard.securefile;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import io.github.runsecure.hkdfguard.abstractions.InvalidKeyFileException;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.platform.unix.UnixFiles;
import io.github.runsecure.hkdfguard.testsupport.WindowsTempDirectory;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Stream;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

class TrustedKeyFileTest {
    private static final SecureRandom RANDOM = new SecureRandom();

    private static byte[] random(int length) {
        var bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    // About the size of a KMS ciphertext blob for a 32-byte DEK.
    private static byte[] wrapped() {
        return random(184);
    }

    private static byte[] readContents(byte[] contents) throws IOException {
        return TrustedKeyFile.readContents(new ByteArrayInputStream(contents), "v1.key");
    }

    private static boolean looksLikePlaintextKey(byte[] contents) {
        return TrustedKeyFile.looksLikePlaintextKey(contents, contents.length);
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

    private static byte[] await(CompletableFuture<byte[]> future) throws Exception {
        try {
            return future.get(10, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
            throw e.getCause() instanceof Exception cause ? cause : e;
        }
    }

    // --- Contents ----------------------------------------------------------------------------

    @Test
    void readContents_AWrappedKey_IsReturnedExactly() throws IOException {
        var wrapped = wrapped();

        assertArrayEquals(wrapped, readContents(wrapped));
    }

    @Test
    void readContents_ExactlyTheLimit_IsAccepted() throws IOException {
        var wrapped = random(WrappedKeyLimits.MAX_BYTES);

        assertArrayEquals(wrapped, readContents(wrapped));
    }

    @Test
    void readContents_Empty_IsRefused() {
        var ex = assertThrows(InvalidKeyFileException.class, () -> readContents(new byte[0]));
        assertTrue(ex.getMessage().contains("empty"));
    }

    @Test
    void readContents_OverTheLimit_IsRefused_ReadingOnlyOneBytePast() {
        var stream = new CountingInputStream(new byte[WrappedKeyLimits.MAX_BYTES * 4]);

        assertThrows(InvalidKeyFileException.class, () -> TrustedKeyFile.readContents(stream, "v1.key"));
        assertEquals(WrappedKeyLimits.MAX_BYTES + 1, stream.position);
    }

    @Test
    void readContents_APlaintextKey_IsRefused_AsExposed() {
        var ex = assertThrows(InvalidKeyFileException.class, () -> readContents(random(32)));
        assertTrue(ex.getMessage().contains("exposed"));
    }

    static Stream<String> plaintextKeysAsText() {
        // Fixed, so the standard and URL-safe encodings always differ: FB EF BE encodes as "++++",
        // FF FF FF as "////". A random key would sometimes encode with neither, merging two rows.
        var key = new byte[32];
        for (var i = 0; i < key.length; i++)
            key[i] = (byte) switch (i % 6) {
                case 0 -> 0xFB;
                case 1 -> 0xEF;
                case 2 -> 0xBE;
                default -> 0xFF;
            };
        var hex = HexFormat.of().withUpperCase().formatHex(key);
        var base64 = Base64.getEncoder().encodeToString(key);
        var urlSafe = base64.replace('+', '-').replace('/', '_');
        return Stream.of(
                hex,
                hex.toLowerCase(Locale.ROOT) + "\n",
                base64,
                base64.replaceAll("=+$", ""),
                urlSafe,
                urlSafe.replaceAll("=+$", "") + "\r\n",
                "  \t" + base64 + " \n");
    }

    @ParameterizedTest
    @MethodSource("plaintextKeysAsText")
    void looksLikePlaintextKey_AKeyWrittenAsText_IsDetected(String text) {
        assertTrue(looksLikePlaintextKey(text.getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void looksLikePlaintextKey_RawKey_IsDetected() {
        assertTrue(looksLikePlaintextKey(random(32)));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",   // one hex digit short
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaazz",  // not hex
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",                        // too short for base64
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",                     // too long for base64
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+-",                       // mixes the two alphabets
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!",                       // not base64
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",                     // 45 characters
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",                      // 44, but padded for 31 bytes
    })
    void looksLikePlaintextKey_OtherText_IsNotDetected(String text) {
        assertFalse(looksLikePlaintextKey(text.getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void looksLikePlaintextKey_TheTestInputsAreTheLengthsTheyClaim() {
        // The rows above are spelt out; this keeps them honest.
        assertEquals(63, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".length());
        assertEquals(42, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".length());
        assertEquals(45, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".length());
        assertEquals(44, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==".length());
    }

    @Test
    void looksLikePlaintextKey_AWrappedKey_IsNotDetected() {
        assertFalse(looksLikePlaintextKey(wrapped()));
        assertFalse(looksLikePlaintextKey(random(TrustedKeyFile.PLAINTEXT_TEXT_SCAN_LIMIT)));
    }

    @Test
    void readAsync_EmptyPath_IsAnArgumentError() {
        assertThrows(IllegalArgumentException.class, () -> TrustedKeyFile.readAsync(Path.of(""), KeyFileTrust.ADMINISTRATORS_ONLY));
    }

    @Test
    void readAsync_NullArguments_AreRefused() {
        assertThrows(NullPointerException.class, () -> TrustedKeyFile.readAsync(null, KeyFileTrust.ADMINISTRATORS_ONLY));
        assertThrows(NullPointerException.class, () -> TrustedKeyFile.readAsync(Path.of("v1.key"), null));
    }

    @Test
    void keyFileTrust_CopiesItsLists_AndRefusesIdsOutOfRange() {
        var sids = new java.util.ArrayList<>(java.util.List.of("S-1-5-21-1-2-3-1005"));
        var trust = new KeyFileTrust(sids, java.util.List.of(), java.util.List.of());
        sids.add("S-1-1-0");

        assertEquals(java.util.List.of("S-1-5-21-1-2-3-1005"), trust.windowsPrincipals());
        assertThrows(IllegalArgumentException.class, () -> KeyFileTrust.ADMINISTRATORS_ONLY.withUnixUserIds(-1));
        assertThrows(IllegalArgumentException.class, () -> KeyFileTrust.ADMINISTRATORS_ONLY.withUnixGroupIds(0x1_0000_0000L));
        assertEquals(java.util.List.of(4294967295L), KeyFileTrust.ADMINISTRATORS_ONLY.withUnixUserIds(4294967295L).unixUserIds());
    }

    // --- Windows, real files -----------------------------------------------------------------

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readAsync_Windows_AFileInTheUsersOwnFolder_IsRefusedByDefault() throws IOException {
        try (var dir = new WindowsTempDirectory()) {
            var path = dir.write("v1.key", wrapped());

            var ex = failure(AccessDeniedException.class, TrustedKeyFile.readAsync(path, KeyFileTrust.ADMINISTRATORS_ONLY));
            assertTrue(ex.getMessage().contains("not trusted"));
        }
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readAsync_Windows_WithTheUserTrusted_ReadsTheFile() throws Exception {
        try (var dir = new WindowsTempDirectory()) {
            var wrapped = wrapped();
            var path = dir.write("v1.key", wrapped);

            assertArrayEquals(wrapped, await(TrustedKeyFile.readAsync(path, trustCurrentWindowsUser())));
        }
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readAsync_Windows_ARelativePath_IsReadFromTheWorkingDirectory() throws Exception {
        try (var dir = new WindowsTempDirectory()) {
            var wrapped = wrapped();
            var path = dir.write("v1.key", wrapped);

            var workingDirectory = Path.of(System.getProperty("user.dir")).toAbsolutePath();
            Assumptions.assumeTrue(workingDirectory.getRoot().equals(path.getRoot()), "The temp folder is on another drive than the working directory.");
            var relative = workingDirectory.relativize(path);
            assertFalse(relative.isAbsolute());
            assertArrayEquals(wrapped, await(TrustedKeyFile.readAsync(relative, trustCurrentWindowsUser())));
        }
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readAsync_Windows_AFileOthersMayWrite_IsRefused_EvenWithTheUserTrusted() throws Exception {
        try (var dir = new WindowsTempDirectory()) {
            var path = dir.write("v1.key", wrapped());
            // Users: Write.
            icacls(path.toString(), "/grant", "*S-1-5-32-545:(W)");

            var ex = failure(AccessDeniedException.class, TrustedKeyFile.readAsync(path, trustCurrentWindowsUser()));
            assertTrue(ex.getMessage().contains("grants"));
        }
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readAsync_Windows_AShortName_IsExpanded_AndTheRealPathChecked() throws Exception {
        try (var dir = new WindowsTempDirectory()) {
            var wrapped = wrapped();
            var path = dir.write("a-long-key-file-name.key", wrapped);
            var shortPath = Path.of(WindowsTempDirectory.shortPath(path.toString()));

            // The full path expands 8.3 names, so the folders checked are the real ones.
            assertArrayEquals(wrapped, await(TrustedKeyFile.readAsync(shortPath, trustCurrentWindowsUser())));
            failure(AccessDeniedException.class, TrustedKeyFile.readAsync(shortPath, KeyFileTrust.ADMINISTRATORS_ONLY));
        }
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readAsync_Windows_AMissingFile_IsNotFound() throws IOException {
        try (var dir = new WindowsTempDirectory()) {
            failure(NoSuchFileException.class, TrustedKeyFile.readAsync(dir.path().resolve("missing.key"), trustCurrentWindowsUser()));
        }
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readAsync_Windows_AFileOpenForWriting_IsRefused() throws IOException {
        try (var dir = new WindowsTempDirectory()) {
            var path = dir.write("v1.key", wrapped());
            try (var writer = new FileOutputStream(path.toFile(), true)) {
                var ex = failure(IOException.class, TrustedKeyFile.readAsync(path, trustCurrentWindowsUser()));
                assertFalse(ex instanceof AccessDeniedException || ex instanceof NoSuchFileException);
                assertNotNull(writer);
            }
        }
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readAsync_Windows_AUncPath_IsRefusedWithoutBeingOpened() {
        var ex = failure(AccessDeniedException.class,
                TrustedKeyFile.readAsync(Path.of("\\\\hkdfguard-no-such-server.invalid\\share\\v1.key"), KeyFileTrust.ADMINISTRATORS_ONLY));
        assertTrue(ex.getMessage().contains("UNC"));
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readAsync_Windows_TrustingEveryone_IsRefused() throws IOException {
        try (var dir = new WindowsTempDirectory()) {
            var path = dir.write("v1.key", wrapped());

            failure(IllegalArgumentException.class, TrustedKeyFile.readAsync(path, KeyFileTrust.ADMINISTRATORS_ONLY.withWindowsPrincipals("S-1-1-0")));
        }
    }

    private static void icacls(String... arguments) throws IOException, InterruptedException {
        var command = new String[arguments.length + 1];
        command[0] = Path.of(System.getenv("SystemRoot"), "System32", "icacls.exe").toString();
        System.arraycopy(arguments, 0, command, 1, arguments.length);
        var process = new ProcessBuilder(command).redirectErrorStream(true).start();
        var output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        assertEquals(0, process.waitFor(), output);
    }

    // --- Linux and macOS, real files ---------------------------------------------------------

    @Test
    @EnabledOnOs(value = {OS.LINUX, OS.MAC}, disabledReason = "Linux and macOS only.")
    void readAsync_Unix_AFileUnderTheSharedTempDirectory_IsRefused() throws IOException {
        // /tmp is writable by everyone (sticky or not), so nothing beneath it is trusted.
        var dir = Files.createDirectory(Path.of("/tmp", "hkdfguard-" + UUID.randomUUID()));
        try {
            var path = Files.write(dir.resolve("v1.key"), wrapped());

            failure(AccessDeniedException.class, TrustedKeyFile.readAsync(path, unixTrustCurrentUser()));
        } finally {
            deleteRecursively(dir);
        }
    }

    @Test
    @EnabledOnOs(value = {OS.LINUX, OS.MAC}, disabledReason = "Linux and macOS only.")
    void readAsync_Unix_AFileTheUserOwns_IsRefusedByDefault() throws IOException {
        Assumptions.assumeFalse(unixTrustCurrentUser().unixUserIds().getFirst() == 0, "Running as root, whose files are trusted.");

        var dir = Files.createDirectory(Path.of("target", "keys-" + UUID.randomUUID()).toAbsolutePath());
        try {
            var path = Files.write(dir.resolve("v1.key"), wrapped());

            failure(AccessDeniedException.class, TrustedKeyFile.readAsync(path, KeyFileTrust.ADMINISTRATORS_ONLY));
        } finally {
            deleteRecursively(dir);
        }
    }

    @Test
    @EnabledOnOs(value = {OS.LINUX, OS.MAC}, disabledReason = "Linux and macOS only.")
    void readAsync_Unix_AMissingFile_IsNotFound() {
        failure(NoSuchFileException.class, TrustedKeyFile.readAsync(Path.of("/hkdfguard-missing-" + UUID.randomUUID() + ".key"), KeyFileTrust.ADMINISTRATORS_ONLY));
    }

    @Test
    @EnabledOnOs(value = {OS.LINUX, OS.MAC}, disabledReason = "Linux and macOS only.")
    void readAsync_Unix_ARootOwnedSystemFile_PassesTheLocationChecks() throws Exception {
        // /etc/hosts: root-owned all the way up, and not a key - so it's refused for its contents
        // (or size), never for where it lives.
        try {
            await(TrustedKeyFile.readAsync(Path.of("/etc/hosts"), KeyFileTrust.ADMINISTRATORS_ONLY));
        } catch (AccessDeniedException e) {
            fail("/etc/hosts was refused for its location: " + e.getMessage());
        } catch (InvalidKeyFileException expected) {
            // Its contents.
        }
    }

    @Test
    @EnabledOnOs(value = {OS.LINUX, OS.MAC}, disabledReason = "Linux and macOS only.")
    void readAsync_Unix_AFileOnlyItsTrustedOwnerCanReplace_IsRead_AndALinkToItFollowedOnlyWhenTrusted() throws Exception {
        // A private directory in the user's home (root's, when running as root): trusted all the way
        // up when the home directory and everything above it are, which the assumption checks.
        var trust = unixTrustCurrentUser();
        var home = Path.of(System.getProperty("user.home"));
        Assumptions.assumeTrue(isPrivatePath(home, trust), "The home directory, or a directory above it, can be written by others.");

        var dir = Files.createTempDirectory(home, "hkdfguard-keys-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try {
            var wrapped = wrapped();
            var path = Files.write(dir.resolve("v1.key"), wrapped);
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
            var link = Files.createSymbolicLink(dir.resolve("current.key"), Path.of("v1.key"));

            assertArrayEquals(wrapped, await(TrustedKeyFile.readAsync(path, trust)));
            assertArrayEquals(wrapped, await(TrustedKeyFile.readAsync(link, trust)));
            assertArrayEquals(wrapped, await(TrustedKeyFile.readAsync(dir.resolve("../" + dir.getFileName() + "/./v1.key"), trust)));
            if (trust.unixUserIds().getFirst() != 0) {
                // The same file and link, owned by a user only the first trust names.
                failure(AccessDeniedException.class, TrustedKeyFile.readAsync(link, KeyFileTrust.ADMINISTRATORS_ONLY));
            }
        } finally {
            deleteRecursively(dir);
        }
    }

    /** True if UnixKeyFileChecks would trust {@code directory} and every directory above it. */
    private static boolean isPrivatePath(Path directory, KeyFileTrust trust) throws IOException {
        for (var item = directory.toRealPath(); item != null; item = item.getParent()) {
            var status = UnixFiles.statusOrNull(item.toString());
            if (status == null)
                return false;
            var trustedOwner = status.ownerId() == 0 || trust.unixUserIds().contains(status.ownerId());
            var groupWritable = status.groupWritable() && !trust.unixGroupIds().contains(status.groupId());
            if (!trustedOwner || groupWritable || status.otherWritable())
                return false;
        }
        // A home directory reached through a link is resolved by the checks themselves.
        return true;
    }

    private static KeyFileTrust unixTrustCurrentUser() throws IOException {
        var probe = Path.of("target", "hkdfguard.trust.probe-" + UUID.randomUUID()).toAbsolutePath();
        Files.write(probe, new byte[0]);
        try {
            // The probe was just created by this process, so its owner and group are this
            // process's effective user and group.
            var status = UnixFiles.statusOrNull(probe.toString());
            assertNotNull(status);
            return KeyFileTrust.ADMINISTRATORS_ONLY.withUnixUserIds(status.ownerId()).withUnixGroupIds(status.groupId());
        } finally {
            Files.delete(probe);
        }
    }

    private static void deleteRecursively(Path dir) throws IOException {
        try (var paths = Files.walk(dir)) {
            for (var item : paths.sorted(java.util.Comparator.reverseOrder()).toList())
                Files.deleteIfExists(item);
        }
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
