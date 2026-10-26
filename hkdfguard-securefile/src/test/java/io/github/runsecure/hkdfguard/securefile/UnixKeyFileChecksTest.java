package io.github.runsecure.hkdfguard.securefile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.NoSuchFileException;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * The Linux and macOS key-file location rules, checked against simulated filesystems so they run
 * on every platform. TrustedKeyFileTest runs them against the real filesystem.
 */
class UnixKeyFileChecksTest {
    private static final long ROOT = 0;
    private static final long DEPLOYER = 1001;
    private static final long APP = 1002;
    private static final long DEPLOYERS_GROUP = 2001;

    private static final int MODE_755 = 0755;
    private static final int MODE_775 = 0775;
    private static final int MODE_1777 = 01777;
    private static final int MODE_640 = 0640;
    private static final int MODE_660 = 0660;
    private static final int MODE_777 = 0777;

    private static final String KEY_FILE = "/etc/hkdfguard/keys/v1.key";

    private static final KeyFileTrust DEPLOYER_TRUST = KeyFileTrust.ADMINISTRATORS_ONLY.withUnixUserIds(DEPLOYER).withUnixGroupIds(DEPLOYERS_GROUP);

    /** A simulated filesystem: what lstat sees, and what each symbolic link holds. */
    private static final class FileSystem {
        final Map<String, UnixFileStatus> entries = new HashMap<>();
        final Map<String, String> links = new HashMap<>();

        FileSystem dir(String path) {
            return dir(path, ROOT, MODE_755, ROOT);
        }

        FileSystem dir(String path, long owner, int mode, long group) {
            entries.put(path, new UnixFileStatus(owner, group, mode, UnixFileType.DIRECTORY));
            return this;
        }

        FileSystem file(String path) {
            return file(path, ROOT, MODE_640, ROOT);
        }

        FileSystem file(String path, long owner, int mode, long group) {
            entries.put(path, new UnixFileStatus(owner, group, mode, UnixFileType.REGULAR_FILE));
            return this;
        }

        FileSystem link(String path, String target) {
            return link(path, target, ROOT);
        }

        FileSystem link(String path, String target, long owner) {
            entries.put(path, new UnixFileStatus(owner, owner, MODE_777, UnixFileType.SYMBOLIC_LINK));
            links.put(path, target);
            return this;
        }

        FileSystem other(String path) {
            entries.put(path, new UnixFileStatus(ROOT, ROOT, MODE_640, UnixFileType.OTHER));
            return this;
        }

        String resolve(String path) throws IOException {
            return resolve(path, KeyFileTrust.ADMINISTRATORS_ONLY);
        }

        String resolve(String path, KeyFileTrust trust) throws IOException {
            return UnixKeyFileChecks.resolveTrusted(path, trust, entries::get, links::get);
        }
    }

    private static FileSystem standard() {
        return new FileSystem().dir("/").dir("/etc").dir("/etc/hkdfguard").dir("/etc/hkdfguard/keys");
    }

    @Test
    void rootOwnedThroughout_Resolves() throws IOException {
        var fs = standard().file(KEY_FILE);

        assertEquals(KEY_FILE, fs.resolve(KEY_FILE));
    }

    @Test
    void readableByOthers_IsNeverRefused() throws IOException {
        var fs = standard().file(KEY_FILE, ROOT, MODE_640 | 0004, ROOT);

        assertEquals(KEY_FILE, fs.resolve(KEY_FILE));
    }

    @Test
    void fileOwnedByTheApplication_IsRefused() {
        var fs = standard().file(KEY_FILE, APP, MODE_640, APP);

        var ex = assertThrows(AccessDeniedException.class, () -> fs.resolve(KEY_FILE));
        assertTrue(ex.getMessage().contains("uid 1002"));
    }

    @Test
    void fileOwnedByATrustedDeployer_Resolves() throws IOException {
        var fs = standard().file(KEY_FILE, DEPLOYER, MODE_640, DEPLOYER);

        assertEquals(KEY_FILE, fs.resolve(KEY_FILE, DEPLOYER_TRUST));
    }

    @Test
    void directoryOwnedByAnUntrustedUser_IsRefused() {
        var fs = standard().dir("/etc/hkdfguard/keys", APP, MODE_755, APP).file(KEY_FILE);

        var ex = assertThrows(AccessDeniedException.class, () -> fs.resolve(KEY_FILE));
        assertTrue(ex.getMessage().contains("'/etc/hkdfguard/keys'"));
    }

    @Test
    void untrustedRoot_IsRefused() {
        var fs = standard().dir("/", ROOT, MODE_777, ROOT).file(KEY_FILE);

        assertThrows(AccessDeniedException.class, () -> fs.resolve(KEY_FILE));
    }

    @Test
    void rootThatCanNotBeExamined_IsRefused() {
        var fs = new FileSystem();

        assertThrows(AccessDeniedException.class, () -> fs.resolve(KEY_FILE));
    }

    @Test
    void worldWritableDirectory_IsRefused_EvenWithTheStickyBit() {
        var fs = new FileSystem().dir("/").dir("/tmp", ROOT, MODE_1777, ROOT).dir("/tmp/keys").file("/tmp/keys/v1.key");

        var ex = assertThrows(AccessDeniedException.class, () -> fs.resolve("/tmp/keys/v1.key"));
        assertTrue(ex.getMessage().contains("writable by every user"));
    }

    @Test
    void worldWritableFile_IsRefused_WhateverIsTrusted() {
        var fs = standard().file(KEY_FILE, ROOT, MODE_777, ROOT);

        assertThrows(AccessDeniedException.class, () -> fs.resolve(KEY_FILE, DEPLOYER_TRUST));
    }

    @Test
    void groupWritable_IsRefused_UnlessTheGroupIsTrusted() throws IOException {
        var fs = standard().dir("/etc/hkdfguard/keys", ROOT, MODE_775, DEPLOYERS_GROUP).file(KEY_FILE, ROOT, MODE_660, DEPLOYERS_GROUP);

        var ex = assertThrows(AccessDeniedException.class, () -> fs.resolve(KEY_FILE));
        assertTrue(ex.getMessage().contains("group 2001"));
        assertEquals(KEY_FILE, fs.resolve(KEY_FILE, DEPLOYER_TRUST));
    }

    @Test
    void groupWritableByAnotherGroup_IsRefused_EvenWithATrustedGroup() {
        var fs = standard().file(KEY_FILE, ROOT, MODE_660, APP);

        assertThrows(AccessDeniedException.class, () -> fs.resolve(KEY_FILE, DEPLOYER_TRUST));
    }

    @Test
    void rootOwnedSymbolicLink_IsFollowed_AndItsTargetChecked() throws IOException {
        // macOS: /etc is a root-owned link to private/etc.
        var fs = new FileSystem().dir("/").link("/etc", "private/etc").dir("/private").dir("/private/etc")
                .dir("/private/etc/hkdfguard").file("/private/etc/hkdfguard/v1.key");

        assertEquals("/private/etc/hkdfguard/v1.key", fs.resolve("/etc/hkdfguard/v1.key"));
    }

    @Test
    void absoluteSymbolicLink_RestartsFromRoot() throws IOException {
        var fs = standard().file(KEY_FILE).dir("/srv").link("/srv/current.key", KEY_FILE);

        assertEquals(KEY_FILE, fs.resolve("/srv/current.key"));
    }

    @Test
    void symbolicLinkOwnedByAnUntrustedUser_IsNotFollowed() {
        var fs = standard().file(KEY_FILE).dir("/srv").link("/srv/current.key", KEY_FILE, APP);

        var ex = assertThrows(AccessDeniedException.class, () -> fs.resolve("/srv/current.key"));
        assertTrue(ex.getMessage().contains("symbolic link owned by uid 1002"));
    }

    @Test
    void symbolicLinkOwnedByATrustedDeployer_IsFollowed() throws IOException {
        var fs = standard().file(KEY_FILE).dir("/srv").link("/srv/current.key", KEY_FILE, DEPLOYER);

        assertEquals(KEY_FILE, fs.resolve("/srv/current.key", DEPLOYER_TRUST));
    }

    @Test
    void symbolicLinkIntoAnUntrustedDirectory_IsRefused() {
        var fs = standard().dir("/home").dir("/home/app", APP, MODE_755, APP).file("/home/app/v1.key", APP, MODE_640, APP)
                .link("/etc/hkdfguard/keys/v1.key", "/home/app/v1.key");

        assertThrows(AccessDeniedException.class, () -> fs.resolve(KEY_FILE));
    }

    @Test
    void symbolicLinkLoop_IsRefused() {
        var fs = new FileSystem().dir("/").link("/a", "/b").link("/b", "/a");

        var ex = assertThrows(AccessDeniedException.class, () -> fs.resolve("/a"));
        assertTrue(ex.getMessage().contains("more than " + UnixKeyFileChecks.MAX_SYMBOLIC_LINKS + " symbolic links"));
    }

    @Test
    void unreadableSymbolicLink_IsRefused() {
        var fs = standard().file(KEY_FILE).dir("/srv").link("/srv/current.key", KEY_FILE);
        fs.links.remove("/srv/current.key");

        assertThrows(AccessDeniedException.class, () -> fs.resolve("/srv/current.key"));
    }

    @Test
    void dotAndDotDot_AreResolvedAfterLinks_TheWayTheKernelDoes() throws IOException {
        var fs = standard().file(KEY_FILE);

        assertEquals(KEY_FILE, fs.resolve("/etc/./hkdfguard/keys/../keys//v1.key"));
        assertEquals(KEY_FILE, fs.resolve("/../etc/hkdfguard/keys/v1.key"));
    }

    @Test
    void missingFile_IsNotFound() {
        var fs = standard();

        assertThrows(NoSuchFileException.class, () -> fs.resolve(KEY_FILE));
    }

    @Test
    void pathThroughAFile_IsNotFound() {
        var fs = standard().file(KEY_FILE);

        assertThrows(NoSuchFileException.class, () -> fs.resolve(KEY_FILE + "/more"));
    }

    @Test
    void directory_IsRefused() {
        var fs = standard();

        var ex = assertThrows(AccessDeniedException.class, () -> fs.resolve("/etc/hkdfguard/keys"));
        assertTrue(ex.getMessage().contains("not a regular file"));
    }

    @Test
    void device_IsRefused() {
        var fs = standard().other(KEY_FILE);

        assertThrows(AccessDeniedException.class, () -> fs.resolve(KEY_FILE));
    }

    @Test
    void relativePath_IsAnArgumentError() {
        assertThrows(IllegalArgumentException.class, () -> standard().resolve("keys/v1.key"));
    }

    @ParameterizedTest
    @CsvSource({
            "/etc/hkdfguard, /etc",
            "/etc, /",
            "/, /",
    })
    void parentOf_IsTheLexicalParent(String path, String parent) {
        assertEquals(parent, UnixKeyFileChecks.parentOf(path));
    }
}
