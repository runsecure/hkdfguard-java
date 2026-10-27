package io.github.runsecure.hkdfguard.platform.unix;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * How a file's status is decoded (on every platform), and the real system calls against this
 * machine's filesystem (Linux and macOS only).
 */
class UnixFilesTest {
    @ParameterizedTest
    @CsvSource({
            "0100644, 0644, REGULAR_FILE",
            "0040755, 0755, DIRECTORY",
            "0041777, 01777, DIRECTORY",
            "0120777, 0777, SYMBOLIC_LINK",
            "0010644, 0644, OTHER",
            "0020666, 0666, OTHER",
            "0104755, 04755, REGULAR_FILE",
    })
    void decode_KeepsThePermissionBits_AndNamesTheType(String rawMode, String permissions, UnixFileType type) {
        var status = UnixFiles.decode(Integer.decode(rawMode), 0, 0);

        assertEquals(Integer.decode(permissions), status.mode());
        assertEquals(type, status.type());
    }

    @Test
    void decode_ReadsUidAndGidAsUnsigned() {
        var status = UnixFiles.decode(0100644, -2, -1);

        assertEquals(0xFFFF_FFFEL, status.ownerId());
        assertEquals(0xFFFF_FFFFL, status.groupId());
    }

    @Test
    void groupAndOtherWritable_ReadTheirOwnBitOnly() {
        assertTrue(new UnixFileStatus(0, 0, 0775, UnixFileType.DIRECTORY).groupWritable());
        assertFalse(new UnixFileStatus(0, 0, 0775, UnixFileType.DIRECTORY).otherWritable());
        assertTrue(new UnixFileStatus(0, 0, 0757, UnixFileType.DIRECTORY).otherWritable());
        assertFalse(new UnixFileStatus(0, 0, 0757, UnixFileType.DIRECTORY).groupWritable());
        assertFalse(new UnixFileStatus(0, 0, 0755, UnixFileType.DIRECTORY).groupWritable());
    }

    @Test
    @EnabledOnOs(value = {OS.LINUX, OS.MAC}, disabledReason = "Linux and macOS only.")
    void statusReadLinkAndProbe_DescribeThisUsersFiles() throws IOException {
        var directory = Files.createTempDirectory("hkdfguard-status-");
        var file = directory.resolve("file");
        var link = directory.resolve("link");
        try {
            Files.createFile(file);
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r-----")); // whatever the umask
            Files.createSymbolicLink(link, Path.of("../some/target"));
            var uid = ((Number) Files.getAttribute(directory, "unix:uid")).longValue();

            var status = UnixFiles.statusOrNull(file.toString());
            assertEquals(UnixFileType.REGULAR_FILE, status.type());
            assertEquals(uid, status.ownerId());
            assertEquals(0640, status.mode());

            var linkStatus = UnixFiles.statusOrNull(link.toString());
            assertEquals(UnixFileType.SYMBOLIC_LINK, linkStatus.type());
            assertEquals("../some/target", UnixFiles.readLink(link.toString()));
            assertNull(UnixFiles.readLink(file.toString()));

            assertEquals(UnixFileType.DIRECTORY, UnixFiles.statusOrNull("/").type());
            assertNull(UnixFiles.statusOrNull(directory.resolve("missing").toString()));
            assertNull(UnixFiles.statusOrNull(file.resolve("under-a-file").toString())); // ENOTDIR
            assertEquals(0, UnixFiles.probe("/"));
            assertNotEquals(0, UnixFiles.probe(directory.resolve("missing").toString()));
        } finally {
            Files.deleteIfExists(link);
            Files.deleteIfExists(file);
            Files.deleteIfExists(directory);
        }
    }
}
