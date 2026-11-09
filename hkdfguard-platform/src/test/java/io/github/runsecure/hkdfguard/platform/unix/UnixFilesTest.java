package io.github.runsecure.hkdfguard.platform.unix;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import org.junit.jupiter.api.Assumptions;

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
    // A system.posix_acl_access value: version 2, then (tag, perm, id) entries, little-endian.
    private static byte[] posixAcl(int[]... entries) {
        var buffer = ByteBuffer.allocate(4 + 8 * entries.length).order(ByteOrder.LITTLE_ENDIAN).putInt(2);
        for (var entry : entries)
            buffer.putShort((short) entry[0]).putShort((short) entry[1]).putInt(entry[2]);
        return buffer.array();
    }

    private static final int USER_OBJ = 0x01;
    private static final int USER = 0x02;
    private static final int GROUP_OBJ = 0x04;
    private static final int GROUP = 0x08;
    private static final int MASK = 0x10;
    private static final int OTHER = 0x20;

    @Test
    void parseLinuxAcl_ReportsNamedWriters_AfterTheMask() throws IOException {
        var acl = posixAcl(new int[] {USER_OBJ, 7, -1}, new int[] {USER, 6, 1005}, new int[] {USER, 4, 1006}, new int[] {GROUP_OBJ, 4, -1},
                new int[] {GROUP, 2, 2005}, new int[] {MASK, 6, -1}, new int[] {OTHER, 4, -1});

        assertEquals(List.of(new UnixAclWriter(UnixAclWriter.Kind.USER, 1005), new UnixAclWriter(UnixAclWriter.Kind.GROUP, 2005)),
                UnixFiles.parseLinuxAcl(acl, "/f"));
    }

    @Test
    void parseLinuxAcl_AMaskWithoutWrite_GrantsNoNamedEntryWrite() throws IOException {
        var acl = posixAcl(new int[] {USER_OBJ, 7, -1}, new int[] {USER, 7, 1005}, new int[] {GROUP_OBJ, 5, -1}, new int[] {MASK, 5, -1},
                new int[] {OTHER, 5, -1});

        assertTrue(UnixFiles.parseLinuxAcl(acl, "/f").isEmpty());
    }

    @Test
    void parseLinuxAcl_TheMinimalAcl_HasNoWritersBeyondTheModeBits() throws IOException {
        var acl = posixAcl(new int[] {USER_OBJ, 6, -1}, new int[] {GROUP_OBJ, 6, -1}, new int[] {OTHER, 6, -1});

        assertTrue(UnixFiles.parseLinuxAcl(acl, "/f").isEmpty());
    }

    @Test
    void parseLinuxAcl_ReadsIdsAsUnsigned() throws IOException {
        var acl = posixAcl(new int[] {USER, 2, -2}, new int[] {MASK, 7, -1});

        assertEquals(List.of(new UnixAclWriter(UnixAclWriter.Kind.USER, 0xFFFF_FFFEL)), UnixFiles.parseLinuxAcl(acl, "/f"));
    }

    @Test
    void parseLinuxAcl_RefusesWhatIsntAVersion2Acl() {
        assertThrows(IOException.class, () -> UnixFiles.parseLinuxAcl(new byte[3], "/f"));
        assertThrows(IOException.class, () -> UnixFiles.parseLinuxAcl(new byte[13], "/f"));
        var version1 = posixAcl(new int[] {USER_OBJ, 6, -1});
        version1[0] = 1;
        assertThrows(IOException.class, () -> UnixFiles.parseLinuxAcl(version1, "/f"));
    }

    // setfacl, where the acl package is installed (GitHub's Ubuntu runners have it): a named user's
    // write shows up as an ACL writer, and the mask taking it away removes it.
    @Test
    @EnabledOnOs(value = OS.LINUX, disabledReason = "Linux only.")
    void status_ReportsAPosixAclWriter_OnLinux() throws Exception {
        Assumptions.assumeTrue(Files.isExecutable(Path.of("/usr/bin/setfacl")), "setfacl isn't installed.");
        var directory = Files.createTempDirectory("hkdfguard-acl-");
        var file = Files.createFile(directory.resolve("file"));
        try {
            run("/usr/bin/setfacl", "-m", "u:65534:rw", file.toString());
            assertEquals(List.of(new UnixAclWriter(UnixAclWriter.Kind.USER, 65534)), UnixFiles.statusOrNull(file.toString()).aclWriters());

            run("/usr/bin/setfacl", "-m", "m::r", file.toString());
            assertTrue(UnixFiles.statusOrNull(file.toString()).aclWriters().isEmpty());

            run("/usr/bin/setfacl", "-m", "g:65534:rwx,m::rwx", directory.toString());
            assertEquals(List.of(new UnixAclWriter(UnixAclWriter.Kind.GROUP, 65534)), UnixFiles.statusOrNull(directory.toString()).aclWriters());
        } finally {
            Files.deleteIfExists(file);
            Files.deleteIfExists(directory);
        }
    }

    // chmod +a: an allow entry granting a modifying right shows up, by the gid "everyone" maps to;
    // a deny entry, a read-only one and one only inherited don't.
    @Test
    @EnabledOnOs(value = OS.MAC, disabledReason = "macOS only.")
    void status_ReportsAnExtendedAclWriter_OnMacOs() throws Exception {
        var directory = Files.createTempDirectory("hkdfguard-acl-");
        var file = Files.createFile(directory.resolve("file"));
        try {
            run("/bin/chmod", "+a", "everyone deny write", file.toString());
            run("/bin/chmod", "+a", "everyone allow read", file.toString());
            assertTrue(UnixFiles.statusOrNull(file.toString()).aclWriters().isEmpty());

            run("/bin/chmod", "+a", "everyone allow append", file.toString());
            assertEquals(List.of(new UnixAclWriter(UnixAclWriter.Kind.GROUP, 12)), UnixFiles.statusOrNull(file.toString()).aclWriters());

            run("/bin/chmod", "+a", "everyone allow add_file,file_inherit,directory_inherit,only_inherit", directory.toString());
            assertTrue(UnixFiles.statusOrNull(directory.toString()).aclWriters().isEmpty());

            run("/bin/chmod", "+a", "everyone allow delete_child", directory.toString());
            assertEquals(List.of(new UnixAclWriter(UnixAclWriter.Kind.GROUP, 12)), UnixFiles.statusOrNull(directory.toString()).aclWriters());
        } finally {
            run("/bin/chmod", "-N", file.toString());
            run("/bin/chmod", "-N", directory.toString());
            Files.deleteIfExists(file);
            Files.deleteIfExists(directory);
        }
    }

    private static void run(String... command) throws IOException, InterruptedException {
        var process = new ProcessBuilder(command).redirectErrorStream(true).start();
        var output = new String(process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
        assertEquals(0, process.waitFor(), String.join(" ", command) + ": " + output);
    }

}
