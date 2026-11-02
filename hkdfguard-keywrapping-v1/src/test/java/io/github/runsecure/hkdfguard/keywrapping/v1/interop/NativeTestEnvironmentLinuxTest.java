package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.opentest4j.TestAbortedException;

/**
 * NativeTestEnvironment.createTempDirectory on Linux: the directory it hands out for key files must
 * be one the native library trusts - private, outside /tmp, /var/tmp and /dev/shm, with no group-
 * or world-writable directory (sticky or not) above it - and where there is none the test is
 * skipped, never passed.
 */
@EnabledOnOs(value = OS.LINUX, disabledReason = "Linux only.")
class NativeTestEnvironmentLinuxTest {
    private static final List<String> STICKY_TEMP_DIRECTORIES = List.of("/tmp", "/var/tmp", "/dev/shm");

    private static long uid() throws IOException {
        return NativeTestEnvironment.linuxEffectiveUserId();
    }

    @Test
    void createTempDirectory_IsPrivate_Trusted_AndOutsideTheStickyTempDirectories() throws IOException {
        var directory = NativeTestEnvironment.createTempDirectory("hkdfguard-helper-");
        try {
            assertTrue(Files.isDirectory(directory));
            try (var entries = Files.list(directory)) {
                assertTrue(entries.findAny().isEmpty(), "not empty");
            }
            assertEquals(directory, directory.toRealPath());
            assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(directory)));
            assertEquals(uid(), ((Number) Files.getAttribute(directory, "unix:uid")).longValue());
            for (var sticky : STICKY_TEMP_DIRECTORIES)
                assertFalse(directory.startsWith(sticky), directory + " is under " + sticky);
            assertNull(NativeTestEnvironment.linuxUntrustedReason(directory, uid()));

            // A key file written there is the user's alone, whatever the umask - and rewriting an
            // existing one, as the tamper tests do, puts its mode back to rw-------.
            var file = NativeTestEnvironment.writeKeyFile(directory.resolve("key.bin"), new byte[132]);
            assertTrue(Files.isRegularFile(file));
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-rw-r--"));
            NativeTestEnvironment.writeKeyFile(file, new byte[132]);
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
        } finally {
            NativeTestEnvironment.deleteRecursively(directory);
        }
        assertFalse(Files.exists(directory), "not cleaned up");
    }

    @Test
    void createTempDirectory_HandsOutADifferentDirectoryEachTime() throws IOException {
        var first = NativeTestEnvironment.createTempDirectory("hkdfguard-helper-");
        try {
            var second = NativeTestEnvironment.createTempDirectory("hkdfguard-helper-");
            try {
                assertNotEquals(first, second);
            } finally {
                NativeTestEnvironment.deleteRecursively(second);
            }
        } finally {
            NativeTestEnvironment.deleteRecursively(first);
        }
    }

    @Test
    void theStickyTempDirectories_AreUntrusted() throws IOException {
        for (var sticky : STICKY_TEMP_DIRECTORIES) {
            var path = Path.of(sticky);
            if (!Files.isDirectory(path))
                continue;
            var reason = NativeTestEnvironment.linuxUntrustedReason(path, uid());
            assertNotNull(reason, sticky + " was trusted");
            assertTrue(reason.contains("writable by group or others"), reason);
        }
    }

    @Test
    void aPrivateDirectoryUnderTmp_IsStillUntrusted() throws IOException {
        // Its own mode is fine; /tmp above it is not, sticky bit or no.
        var underTmp = Files.createTempDirectory(Path.of("/tmp"), "hkdfguard-helper-",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try {
            var reason = NativeTestEnvironment.linuxUntrustedReason(underTmp, uid());

            assertNotNull(reason);
            assertTrue(reason.startsWith("/tmp "), reason);
        } finally {
            NativeTestEnvironment.deleteRecursively(underTmp);
        }
    }

    @Test
    void aGroupWritableDirectory_IsUntrusted() throws IOException {
        var directory = NativeTestEnvironment.createTempDirectory("hkdfguard-helper-");
        try {
            var shared = Files.createDirectory(directory.resolve("shared"));
            Files.setPosixFilePermissions(shared, PosixFilePermissions.fromString("rwxrwx---"));

            var reason = NativeTestEnvironment.linuxUntrustedReason(shared, uid());

            assertNotNull(reason);
            assertTrue(reason.startsWith(shared + " "), reason);
        } finally {
            NativeTestEnvironment.deleteRecursively(directory);
        }
    }

    @Test
    void aRuntimeDirectoryUnderTmp_IsPassedOver_ForTheHomeDirectory() throws IOException {
        var fakeRuntime = Files.createTempDirectory(Path.of("/tmp"), "hkdfguard-runtime-",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
        try {
            var home = System.getenv("HOME");
            var directory = NativeTestEnvironment.linuxPrivateDirectory("hkdfguard-helper-", fakeRuntime.toString(), home, uid());
            try {
                assertFalse(directory.startsWith(fakeRuntime.toRealPath()), directory.toString());
                assertTrue(directory.startsWith(Path.of(home).toRealPath().resolve(NativeTestEnvironment.HOME_TEST_DIRECTORY)), directory.toString());
            } finally {
                NativeTestEnvironment.deleteRecursively(directory);
            }
        } finally {
            NativeTestEnvironment.deleteRecursively(fakeRuntime);
        }
    }

    @Test
    void aTrustedRuntimeDirectory_IsPreferred() throws IOException {
        // A private directory made by the helper itself stands in for $XDG_RUNTIME_DIR.
        var runtime = NativeTestEnvironment.createTempDirectory("hkdfguard-runtime-");
        try {
            var directory = NativeTestEnvironment.linuxPrivateDirectory("hkdfguard-helper-", runtime.toString(), "/nonexistent-home", uid());

            assertEquals(runtime, directory.getParent());
        } finally {
            NativeTestEnvironment.deleteRecursively(runtime);
        }
    }

    @Test
    void withNoTrustedLocation_TheTestIsSkipped_NeverPassed() throws IOException {
        var uid = uid();
        var skipped = assertThrows(TestAbortedException.class,
                () -> NativeTestEnvironment.linuxPrivateDirectory("hkdfguard-helper-", "/tmp", "/tmp", uid));

        assertTrue(skipped.getMessage().contains("No private directory for key files"), skipped.getMessage());
        assertTrue(skipped.getMessage().contains("/tmp is writable by group or others"), skipped.getMessage());

        var unset = assertThrows(TestAbortedException.class, () -> NativeTestEnvironment.linuxPrivateDirectory("hkdfguard-helper-", null, null, uid));
        assertTrue(unset.getMessage().contains("XDG_RUNTIME_DIR is not set") && unset.getMessage().contains("$HOME is not set"), unset.getMessage());
    }
}
