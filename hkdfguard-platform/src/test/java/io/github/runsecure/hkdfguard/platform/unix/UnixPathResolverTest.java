package io.github.runsecure.hkdfguard.platform.unix;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.runsecure.hkdfguard.platform.unix.UnixPathResolver.Resolution;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Where the shared path walk stops, and why, against simulated filesystems, so it runs on every
 * platform. The rule here - owned by root or uid 1000, writable by no one else - stands in for the
 * callers' own: the native library loader's and the key-file checks' tests hold the walk to theirs.
 */
class UnixPathResolverTest {
    private static final long ROOT = 0;
    private static final long TRUSTED = 1000;
    private static final long STRANGER = 2000;

    /** A simulated filesystem: what lstat sees, and what each symbolic link holds. */
    private static final class FileSystem {
        final Map<String, UnixFileStatus> entries = new HashMap<>();
        final Map<String, String> links = new HashMap<>();

        FileSystem dir(String path, long owner, int mode) {
            entries.put(path, new UnixFileStatus(owner, owner, mode, UnixFileType.DIRECTORY));
            return this;
        }

        FileSystem file(String path, long owner) {
            entries.put(path, new UnixFileStatus(owner, owner, 0644, UnixFileType.REGULAR_FILE));
            return this;
        }

        FileSystem link(String path, String target, long owner) {
            entries.put(path, new UnixFileStatus(owner, owner, 0777, UnixFileType.SYMBOLIC_LINK));
            links.put(path, target);
            return this;
        }

        Resolution resolve(String path) throws IOException {
            return UnixPathResolver.resolve(path, entries::get, links::get,
                    status -> (status.ownerId() == ROOT || status.ownerId() == TRUSTED) && !status.groupWritable() && !status.otherWritable(),
                    uid -> uid == ROOT || uid == TRUSTED);
        }
    }

    private static FileSystem standard() {
        return new FileSystem()
                .dir("/", ROOT, 0755)
                .dir("/etc", ROOT, 0755)
                .dir("/etc/app", TRUSTED, 0755)
                .file("/etc/app/key", TRUSTED)
                .dir("/tmp", ROOT, 01777)
                .file("/tmp/key", ROOT)
                .dir("/home", ROOT, 0755)
                .dir("/home/stranger", STRANGER, 0755)
                .file("/home/stranger/key", ROOT);
    }

    @Test
    void aTrustedPath_Resolves() throws IOException {
        assertEquals(new Resolution.Resolved("/etc/app/key", UnixFileType.REGULAR_FILE), standard().resolve("/etc/app/key"));
        assertEquals(new Resolution.Resolved("/etc", UnixFileType.DIRECTORY), standard().resolve("/etc/"));
        assertEquals(new Resolution.Resolved("/", UnixFileType.DIRECTORY), standard().resolve("/"));
    }

    @Test
    void emptyAndDotComponents_AreSkipped_AndDotDotIsLexical() throws IOException {
        assertEquals(new Resolution.Resolved("/etc/app/key", UnixFileType.REGULAR_FILE), standard().resolve("/etc//./app/../app/key"));
        assertEquals(new Resolution.Resolved("/", UnixFileType.DIRECTORY), standard().resolve("/.."));
    }

    @Test
    void aTrustedLink_IsFollowed_AndDotDotAfterItIsResolvedAgainstItsTarget() throws IOException {
        var fs = standard().link("/opt", "etc/app", ROOT);

        assertEquals(new Resolution.Resolved("/etc/app/key", UnixFileType.REGULAR_FILE), fs.resolve("/opt/key"));
        // /opt -> /etc/app: "/opt/.." is /etc, not /.
        assertEquals(new Resolution.Resolved("/etc", UnixFileType.DIRECTORY), fs.resolve("/opt/.."));
    }

    @Test
    void anAbsoluteLinkTarget_RestartsFromRoot() throws IOException {
        var fs = standard().link("/etc/app/current", "/etc/app/key", TRUSTED);

        assertEquals(new Resolution.Resolved("/etc/app/key", UnixFileType.REGULAR_FILE), fs.resolve("/etc/app/current"));
    }

    @Test
    void anUntrustedComponent_StopsTheWalkThere() throws IOException {
        var fs = standard();

        assertEquals(new Resolution.UntrustedComponent("/tmp", fs.entries.get("/tmp")), fs.resolve("/tmp/key"));
        assertEquals(new Resolution.UntrustedComponent("/home/stranger", fs.entries.get("/home/stranger")), fs.resolve("/home/stranger/key"));
    }

    @Test
    void anUntrustedRoot_IsReportedAsSlash() throws IOException {
        var fs = standard().dir("/", ROOT, 0777);

        assertEquals(new Resolution.UntrustedComponent("/", fs.entries.get("/")), fs.resolve("/etc/app/key"));
    }

    @Test
    void anUnreadableRoot_IsReported() throws IOException {
        assertEquals(new Resolution.RootUnreadable(), new FileSystem().resolve("/etc/app/key"));
    }

    @Test
    void anUntrustedLink_IsNotFollowed() throws IOException {
        var fs = standard().link("/etc/app/current", "key", STRANGER);

        assertEquals(new Resolution.UntrustedLink("/etc/app/current", fs.entries.get("/etc/app/current")), fs.resolve("/etc/app/current"));
    }

    @Test
    void aLinkLoop_StopsAtTheKernelsLimit() throws IOException {
        var fs = standard().link("/a", "/b", ROOT).link("/b", "/a", ROOT);

        assertEquals(new Resolution.TooManyLinks(), fs.resolve("/a/key"));
    }

    @Test
    void exactlyTheKernelsLimitOfLinks_IsFollowed() throws IOException {
        var fs = standard();
        for (var i = 0; i < UnixPathResolver.MAX_SYMBOLIC_LINKS - 1; i++)
            fs.link("/l" + i, "/l" + (i + 1), ROOT);
        fs.link("/l" + (UnixPathResolver.MAX_SYMBOLIC_LINKS - 1), "/etc/app/key", ROOT);

        assertEquals(new Resolution.Resolved("/etc/app/key", UnixFileType.REGULAR_FILE), fs.resolve("/l0"));
    }

    @Test
    void aLinkWhoseTargetCantBeRead_IsReported() throws IOException {
        var fs = standard();
        fs.entries.put("/broken", new UnixFileStatus(ROOT, ROOT, 0777, UnixFileType.SYMBOLIC_LINK));

        assertEquals(new Resolution.UnreadableLink("/broken"), fs.resolve("/broken/key"));
    }

    @Test
    void aMissingComponent_IsReportedWhereTheWalkStopped() throws IOException {
        assertEquals(new Resolution.Missing("/etc/missing"), standard().resolve("/etc/missing/key"));
    }

    @Test
    void aPathThroughAFile_IsReportedAsNotADirectory() throws IOException {
        assertEquals(new Resolution.NotADirectory("/etc/app/key"), standard().resolve("/etc/app/key/more"));
    }

    @Test
    void aRelativePath_IsAnArgumentError() {
        assertThrows(IllegalArgumentException.class, () -> standard().resolve("etc/app/key"));
    }

    @Test
    void aStatusReaderFailure_Propagates() {
        var failure = new IOException("EIO");

        var thrown = assertThrows(IOException.class, () -> UnixPathResolver.resolve("/etc", path -> {
            throw failure;
        }, path -> null, status -> true, uid -> true));
        assertEquals(failure, thrown);
    }

    @ParameterizedTest
    @CsvSource({"/, /", "/usr, /", "/usr/lib, /usr", "/etc/hkdfguard, /etc"})
    void parentOf_IsTheLexicalParent(String path, String parent) {
        assertEquals(parent, UnixPathResolver.parentOf(path));
    }
}
