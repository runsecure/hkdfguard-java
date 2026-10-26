package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.keywrapping.v1.NativeLibraryNotFoundException;
import io.github.runsecure.hkdfguard.platform.unix.UnixFileStatus;
import io.github.runsecure.hkdfguard.platform.unix.UnixFileType;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The macOS loader's decisions - which install to use and whether its path and signature can be
 * trusted - checked against simulated filesystems, so they run on every platform. The thin macOS
 * system-call layer (MacOsNative) only runs on a Mac.
 */
class MacOsNativeLibraryLoaderTest {
    private static final long ROOT = 0;
    private static final long USER = 501;
    private static final long OTHER_USER = 502;
    private static final long WHEEL = 0;
    private static final long ADMIN = 80;
    private static final long STAFF = 20;
    private static final String HOME = "/Users/dev";

    private static final int MODE_755 = 0755;
    private static final int MODE_775 = 0775;
    private static final int MODE_644 = 0644;
    private static final int MODE_700 = 0700;

    private static final List<Long> SYSTEM_OWNERS = List.of(ROOT);
    private static final List<Long> USER_OWNERS = List.of(ROOT, USER);

    private static UnixFileStatus dir(long owner, long group, int mode) {
        return new UnixFileStatus(owner, group, mode, UnixFileType.DIRECTORY);
    }

    private static UnixFileStatus file(long owner, long group, int mode) {
        return new UnixFileStatus(owner, group, mode, UnixFileType.REGULAR_FILE);
    }

    // A standard system install: /Library/Application Support is root:admin and group-writable.
    private static Map<String, UnixFileStatus> systemInstall() {
        var fs = new HashMap<String, UnixFileStatus>();
        fs.put("/", dir(ROOT, WHEEL, MODE_755));
        fs.put("/Library", dir(ROOT, WHEEL, MODE_755));
        fs.put("/Library/Application Support", dir(ROOT, ADMIN, MODE_775));
        fs.put("/Library/Application Support/HkdfGuard", dir(ROOT, WHEEL, MODE_755));
        fs.put("/Library/Application Support/HkdfGuard/v1", dir(ROOT, WHEEL, MODE_755));
        fs.put(MacOsNativeLibraryLoader.systemPath(), file(ROOT, WHEEL, MODE_644));
        return fs;
    }

    // A standard per-user install under a user-owned home.
    private static Map<String, UnixFileStatus> userInstall() {
        var fs = new HashMap<String, UnixFileStatus>();
        fs.put("/", dir(ROOT, WHEEL, MODE_755));
        fs.put("/Users", dir(ROOT, ADMIN, MODE_755));
        fs.put(HOME, dir(USER, STAFF, MODE_755));
        fs.put(HOME + "/.hkdfguard", dir(USER, STAFF, MODE_700));
        fs.put(HOME + "/.hkdfguard/v1", dir(USER, STAFF, MODE_700));
        fs.put(MacOsNativeLibraryLoader.userPath(HOME), file(USER, STAFF, MODE_644));
        return fs;
    }

    private static void verify(Map<String, UnixFileStatus> filesystem, String path, List<Long> owners) {
        MacOsNativeLibraryLoader.verifyLocation(path, filesystem::get, owners);
    }

    // --- Platform -------------------------------------------------------------------------------

    @ParameterizedTest
    @ValueSource(strings = {"13.0", "15.4", "26.0", "14.7.1"})
    void requireSupportedPlatform_AcceptsArm64_OnMacOs13OrLater(String version) {
        assertDoesNotThrow(() -> MacOsNativeLibraryLoader.requireSupportedPlatform(CpuArchitecture.ARM64, version));
    }

    @Test
    void requireSupportedPlatform_RefusesX64_NamingRosetta() {
        var ex = assertThrows(UnsupportedOperationException.class,
                () -> MacOsNativeLibraryLoader.requireSupportedPlatform(CpuArchitecture.X64, "15.0"));

        assertTrue(ex.getMessage().contains("Apple silicon"));
        assertTrue(ex.getMessage().contains("Rosetta"));
    }

    @ParameterizedTest
    @EnumSource(value = CpuArchitecture.class, names = {"X86", "ARM", "OTHER"})
    void requireSupportedPlatform_RefusesEveryOtherArchitecture(CpuArchitecture architecture) {
        var ex = assertThrows(UnsupportedOperationException.class,
                () -> MacOsNativeLibraryLoader.requireSupportedPlatform(architecture, "15.0"));

        assertTrue(ex.getMessage().contains(architecture.toString()));
    }

    @Test
    void requireSupportedPlatform_RefusesMacOsOlderThan13() {
        var ex = assertThrows(UnsupportedOperationException.class,
                () -> MacOsNativeLibraryLoader.requireSupportedPlatform(CpuArchitecture.ARM64, "12.7.6"));

        assertTrue(ex.getMessage().contains("macOS 13"));
        assertTrue(ex.getMessage().contains("12.7.6"));
    }

    // --- Locations ------------------------------------------------------------------------------

    @Test
    void theTwoLocations_AreTheAgreedPaths() {
        assertEquals("/Library/Application Support/HkdfGuard/v1/libhkdfguard.dylib", MacOsNativeLibraryLoader.systemPath());
        assertEquals("/Users/dev/.hkdfguard/v1/libhkdfguard.dylib", MacOsNativeLibraryLoader.userPath("/Users/dev"));
        assertEquals("/Users/dev/.hkdfguard/v1/libhkdfguard.dylib", MacOsNativeLibraryLoader.userPath("/Users/dev/"));
    }

    // lstat results for choosePath's probe.
    private static final int PRESENT = 0;
    private static final int ENOENT = 2;
    private static final int EACCES = 13;
    private static final int ENOTDIR = 20;

    @Test
    void choosePath_PrefersTheSystemInstall_EvenWhenAUserInstallExists() {
        var choice = MacOsNativeLibraryLoader.choosePath(path -> PRESENT, HOME);

        assertEquals(MacOsNativeLibraryLoader.systemPath(), choice.path());
        assertTrue(choice.isSystem());
    }

    @ParameterizedTest
    @ValueSource(ints = {ENOENT, ENOTDIR}) // ENOTDIR: a parent of the system path is a file - still just "not there"
    void choosePath_UsesTheUserInstall_OnlyWhenThereIsNoSystemInstall(int systemErrno) {
        var user = MacOsNativeLibraryLoader.userPath(HOME);

        var choice = MacOsNativeLibraryLoader.choosePath(path -> path.equals(user) ? PRESENT : systemErrno, HOME);

        assertEquals(user, choice.path());
        assertFalse(choice.isSystem());
    }

    @ParameterizedTest
    @ValueSource(ints = {EACCES, 62, 5}) // EACCES, ELOOP, EIO
    void choosePath_WhenTheSystemInstallCannotBeExamined_RefusesInsteadOfFallingBack(int errno) {
        var probed = new ArrayList<String>();

        var ex = assertThrows(SecurityException.class, () -> MacOsNativeLibraryLoader.choosePath(path -> {
            probed.add(path);
            return errno;
        }, HOME));

        assertTrue(ex.getMessage().contains(MacOsNativeLibraryLoader.systemPath()));
        assertTrue(ex.getMessage().contains("errno " + errno));
        assertEquals(List.of(MacOsNativeLibraryLoader.systemPath()), probed); // the user install was never even considered
    }

    @Test
    void choosePath_WhenTheUserInstallCannotBeExamined_Refuses() {
        var ex = assertThrows(SecurityException.class, () ->
                MacOsNativeLibraryLoader.choosePath(path -> path.equals(MacOsNativeLibraryLoader.systemPath()) ? ENOENT : EACCES, HOME));

        assertTrue(ex.getMessage().contains(MacOsNativeLibraryLoader.userPath(HOME)));
    }

    @Test
    void choosePath_WithNeitherInstallUsable_ThrowsNamingBothLocations() {
        var ex = assertThrows(NativeLibraryNotFoundException.class, () ->
                MacOsNativeLibraryLoader.choosePath(path -> ENOENT, HOME));

        assertTrue(ex.getMessage().contains(MacOsNativeLibraryLoader.systemPath()));
        assertTrue(ex.getMessage().contains(MacOsNativeLibraryLoader.userPath(HOME)));
    }

    @ParameterizedTest
    @CsvSource(nullValues = "NULL", value = {"NULL", "''", "relative/home"}) // no account entry; no home; a relative home
    void choosePath_WithNoUsableAccountHome_ConsidersOnlyTheSystemInstall(String home) {
        var probed = new ArrayList<String>();

        var ex = assertThrows(NativeLibraryNotFoundException.class, () ->
                MacOsNativeLibraryLoader.choosePath(path -> { probed.add(path); return !path.startsWith("/") && path.endsWith(".dylib") ? PRESENT : ENOENT; }, home));

        assertEquals(List.of(MacOsNativeLibraryLoader.systemPath()), probed);
        assertTrue(ex.getMessage().contains(MacOsNativeLibraryLoader.systemPath()));
        assertFalse(ex.getMessage().contains(".hkdfguard"));
    }

    @Test
    void choosePath_WithNoUsableAccountHome_StillUsesTheSystemInstall() {
        var choice = MacOsNativeLibraryLoader.choosePath(path -> PRESENT, null);

        assertEquals(MacOsNativeLibraryLoader.systemPath(), choice.path());
        assertTrue(choice.isSystem());
    }

    // --- The library's version ------------------------------------------------------------------

    private static final int ARM64 = 0x0100000C;
    private static final int X86_64 = 0x01000007;

    private record Command(int cmd, int size, Integer version) {
    }

    // A thin Mach-O 64 header followed by the given load commands.
    private static byte[] machO(int cpuType, Command... commands) {
        var bodySize = 0;
        for (var c : commands)
            bodySize += c.size();
        var buffer = java.nio.ByteBuffer.allocate(32 + bodySize).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(0, 0xFEEDFACF).putInt(4, cpuType).putInt(16, commands.length).putInt(20, bodySize);
        var at = 32;
        for (var c : commands) {
            buffer.putInt(at, c.cmd()).putInt(at + 4, c.size());
            if (c.version() != null && c.size() >= 24)
                buffer.putInt(at + 16, c.version());
            at += c.size();
        }
        return buffer.array();
    }

    private static byte[] dylib(int version, int cpuType) {
        return machO(cpuType, new Command(0x19, 72, null), new Command(0xD, 48, version), new Command(0x32, 32, null));
    }

    private static byte[] dylib(int version) {
        return dylib(version, ARM64);
    }

    // A universal file: a FAT_MAGIC header with one 20-byte entry per slice, slices at 4 KiB boundaries.
    private static byte[] fat(int[] cpuTypes, byte[]... slices) {
        var align = 4096;
        var buffer = java.nio.ByteBuffer.allocate(align * (slices.length + 1)).order(java.nio.ByteOrder.BIG_ENDIAN);
        buffer.putInt(0, 0xCAFEBABE).putInt(4, slices.length);
        for (var i = 0; i < slices.length; i++) {
            var offset = align * (i + 1);
            buffer.putInt(8 + i * 20, cpuTypes[i]).putInt(8 + i * 20 + 8, offset).putInt(8 + i * 20 + 12, slices[i].length);
            buffer.put(offset, slices[i]);
        }
        return buffer.array();
    }

    private static byte[] patch(byte[] data, int at, int value, java.nio.ByteOrder order) {
        var copy = data.clone();
        java.nio.ByteBuffer.wrap(copy).order(order).putInt(at, value);
        return copy;
    }

    private static byte[] patch(byte[] data, int at, int value) {
        return patch(data, at, value, java.nio.ByteOrder.LITTLE_ENDIAN);
    }

    @ParameterizedTest
    @ValueSource(ints = {0x0000_0900, 0x0000_0901, 0x0001_0000}) // the minimum (0.9.0), 0.9.1, 1.0.0
    void verifyVersion_AcceptsTheMinimumAndNewer(int version) {
        assertEquals(version, MacOsNativeLibraryLoader.readLibraryVersion(dylib(version)));
        assertDoesNotThrow(() -> MacOsNativeLibraryLoader.verifyVersion("/x.dylib", dylib(version)));
    }

    @ParameterizedTest
    @CsvSource({"0x0800,0.8.0", "0x08FF,0.8.255", "0x0000,0.0.0"})
    void verifyVersion_RefusesAnOlderRelease_NamingBothVersions(String hex, String shown) {
        var version = Integer.decode(hex);
        var ex = assertThrows(SecurityException.class, () -> MacOsNativeLibraryLoader.verifyVersion("/x.dylib", dylib(version)));

        assertTrue(ex.getMessage().contains("version " + shown), ex.getMessage());
        assertTrue(ex.getMessage().contains("(0.9.0)"), ex.getMessage());
    }

    static java.util.stream.Stream<org.junit.jupiter.params.provider.Arguments> unreadableLibraries() {
        var good = dylib(0x0900);
        return java.util.stream.Stream.of(
                org.junit.jupiter.params.provider.Arguments.of("empty", new byte[0]),
                org.junit.jupiter.params.provider.Arguments.of("truncated header", java.util.Arrays.copyOf(good, 20)),
                org.junit.jupiter.params.provider.Arguments.of("wrong magic", patch(good, 0, 0x464C457F)),
                org.junit.jupiter.params.provider.Arguments.of("x86_64 only", dylib(0x0900, X86_64)),
                org.junit.jupiter.params.provider.Arguments.of("no LC_ID_DYLIB", machO(ARM64, new Command(0x19, 72, null), new Command(0x32, 32, null))),
                org.junit.jupiter.params.provider.Arguments.of("LC_ID_DYLIB too short", machO(ARM64, new Command(0xD, 16, null))),
                org.junit.jupiter.params.provider.Arguments.of("cmdsize zero", patch(good, 36, 0)),
                org.junit.jupiter.params.provider.Arguments.of("cmdsize not a multiple of 8", patch(good, 36, 70)),
                org.junit.jupiter.params.provider.Arguments.of("cmdsize past the commands", patch(good, 36, 0x7FFF_FFF8)),
                org.junit.jupiter.params.provider.Arguments.of("sizeofcmds past the data", patch(good, 20, 0x7FFF_FFF8)),
                org.junit.jupiter.params.provider.Arguments.of("ncmds larger than sizeofcmds allows", patch(good, 16, 1000)),
                org.junit.jupiter.params.provider.Arguments.of("fat without an arm64 slice", fat(new int[] {X86_64}, dylib(0x0900, X86_64))),
                org.junit.jupiter.params.provider.Arguments.of("fat with an arm64 slice outside the data",
                        patch(fat(new int[] {ARM64}, good), 16, 0x0100_0000, java.nio.ByteOrder.BIG_ENDIAN)),
                org.junit.jupiter.params.provider.Arguments.of("fat claiming more slices than fit",
                        patch(fat(new int[] {ARM64}, good), 4, 1000, java.nio.ByteOrder.BIG_ENDIAN)));
    }

    @ParameterizedTest(name = "{0}")
    @org.junit.jupiter.params.provider.MethodSource("unreadableLibraries")
    void verifyVersion_RefusesAFileWhoseVersionCannotBeRead(String why, byte[] data) {
        assertEquals(null, MacOsNativeLibraryLoader.readLibraryVersion(data), why);
        var ex = assertThrows(SecurityException.class, () -> MacOsNativeLibraryLoader.verifyVersion("/x.dylib", data));
        assertTrue(ex.getMessage().contains("version can be read"), ex.getMessage());
    }

    @Test
    void readLibraryVersion_ReadsTheArm64SliceOfAUniversalFile() {
        var universal = fat(new int[] {X86_64, ARM64}, dylib(0x0800, X86_64), dylib(0x0902));

        assertEquals(0x0902, MacOsNativeLibraryLoader.readLibraryVersion(universal));
    }

    @Test
    void theInstalledLibrary_WhenPresent_PassesTheVersionCheck() throws Exception {
        var path = java.nio.file.Path.of(MacOsNativeLibraryLoader.systemPath());
        org.junit.jupiter.api.Assumptions.assumeTrue(java.nio.file.Files.exists(path), "the native library is not installed on this host");
        byte[] head;
        try (var stream = java.nio.file.Files.newInputStream(path)) {
            head = stream.readNBytes(MacOsNativeLibraryLoader.VERSION_READ_LIMIT);
        }

        var version = MacOsNativeLibraryLoader.readLibraryVersion(head);
        assertTrue(version != null && Integer.compareUnsigned(version, MacOsNativeLibraryLoader.MINIMUM_LIBRARY_VERSION) >= 0,
                "installed version " + (version == null ? "unreadable" : MacOsNativeLibraryLoader.formatVersion(version)));
        assertDoesNotThrow(() -> MacOsNativeLibraryLoader.verifyVersion(path.toString(), head));
    }

    @Test
    void accountHomeDirectory_OnMacOs_IsAnExistingAbsoluteFolder() {
        org.junit.jupiter.api.Assumptions.assumeTrue(System.getProperty("os.name", "").startsWith("Mac"), "macOS only");

        var home = MacOsNative.accountHomeDirectory();

        assertTrue(home != null && home.startsWith("/") && java.nio.file.Files.isDirectory(java.nio.file.Path.of(home)), String.valueOf(home));
    }

    @ParameterizedTest
    @CsvSource(nullValues = "NULL", value = {"/a/b/c.dylib,/a/b", "/a/b/,/a", "/a,/", "/,NULL"})
    void parentOf_WalksSlashSeparatedPathsUpToRoot(String path, String parent) {
        assertEquals(parent, MacOsNativeLibraryLoader.parentOf(path));
    }

    // --- Path integrity ---------------------------------------------------------------------------

    @Test
    void aStandardSystemInstall_Passes() {
        assertDoesNotThrow(() -> verify(systemInstall(), MacOsNativeLibraryLoader.systemPath(), SYSTEM_OWNERS));
    }

    @Test
    void aStandardUserInstall_Passes() {
        assertDoesNotThrow(() -> verify(userInstall(), MacOsNativeLibraryLoader.userPath(HOME), USER_OWNERS));
    }

    @Test
    void aSystemInstall_OwnedByAUser_IsRefused() {
        var fs = systemInstall();
        fs.put("/Library/Application Support/HkdfGuard/v1", dir(USER, STAFF, MODE_755));

        var ex = assertThrows(SecurityException.class, () -> verify(fs, MacOsNativeLibraryLoader.systemPath(), SYSTEM_OWNERS));

        assertTrue(ex.getMessage().contains("owned by uid 501"));
        assertTrue(ex.getMessage().contains("owned by root."));
    }

    @Test
    void aUserInstall_OwnedByAnotherUser_IsRefused() {
        var fs = userInstall();
        fs.put(MacOsNativeLibraryLoader.userPath(HOME), file(OTHER_USER, STAFF, MODE_644));

        var ex = assertThrows(SecurityException.class, () -> verify(fs, MacOsNativeLibraryLoader.userPath(HOME), USER_OWNERS));

        assertTrue(ex.getMessage().contains("owned by uid 502"));
        assertTrue(ex.getMessage().contains("root or the current user"));
    }

    @Test
    void anyWorldWritableComponent_IsRefused() {
        var fs = userInstall();
        fs.put(HOME + "/.hkdfguard", dir(USER, STAFF, MODE_700 | UnixFileStatus.OTHER_WRITE));

        var ex = assertThrows(SecurityException.class, () -> verify(fs, MacOsNativeLibraryLoader.userPath(HOME), USER_OWNERS));

        assertTrue(ex.getMessage().contains("writable by every user"));
    }

    @Test
    void aGroupWritableComponent_OwnedByAUser_IsRefused() {
        var fs = userInstall();
        fs.put(HOME, dir(USER, STAFF, MODE_775));

        var ex = assertThrows(SecurityException.class, () -> verify(fs, MacOsNativeLibraryLoader.userPath(HOME), USER_OWNERS));

        assertTrue(ex.getMessage().contains("writable by group 20"));
    }

    @Test
    void aGroupWritableRootDirectory_IsRefused_UnlessTheGroupIsWheelOrAdmin() {
        var fs = systemInstall();
        fs.put("/Library/Application Support", dir(ROOT, STAFF, MODE_775));

        assertThrows(SecurityException.class, () -> verify(fs, MacOsNativeLibraryLoader.systemPath(), SYSTEM_OWNERS));

        fs.put("/Library/Application Support", dir(ROOT, WHEEL, MODE_775));
        assertDoesNotThrow(() -> verify(fs, MacOsNativeLibraryLoader.systemPath(), SYSTEM_OWNERS));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/", "/Library", "/Library/Application Support"})
    void theSystemDirectoriesAboveASystemInstall_MayBeAdminWritable(String directory) {
        var fs = systemInstall();
        fs.put(directory, dir(ROOT, ADMIN, MODE_775));

        assertDoesNotThrow(() -> verify(fs, MacOsNativeLibraryLoader.systemPath(), SYSTEM_OWNERS));
    }

    @Test
    void users_MayBeAdminWritable_AboveAUserInstall() {
        var fs = userInstall();
        fs.put("/Users", dir(ROOT, ADMIN, MODE_775));

        assertDoesNotThrow(() -> verify(fs, MacOsNativeLibraryLoader.userPath(HOME), USER_OWNERS));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/Library/Application Support/HkdfGuard", "/Library/Application Support/HkdfGuard/v1"})
    void theInstallsOwnDirectories_AreNeverAdminWritable_EvenWhenRootOwned(String directory) {
        for (var group : new long[] {WHEEL, ADMIN}) {
            var fs = systemInstall();
            fs.put(directory, dir(ROOT, group, MODE_775));

            var ex = assertThrows(SecurityException.class, () -> verify(fs, MacOsNativeLibraryLoader.systemPath(), SYSTEM_OWNERS));

            assertTrue(ex.getMessage().contains("'" + directory + "' is writable by group " + group));
        }
    }

    @Test
    void theLibraryFile_IsNeverAdminWritable_EvenWhenRootOwned() {
        var fs = systemInstall();
        fs.put(MacOsNativeLibraryLoader.systemPath(), file(ROOT, ADMIN, MODE_644 | UnixFileStatus.GROUP_WRITE));

        assertThrows(SecurityException.class, () -> verify(fs, MacOsNativeLibraryLoader.systemPath(), SYSTEM_OWNERS));
    }

    @Test
    void anotherRootOwnedDirectory_IsNotAdminWritable_JustBecauseItLooksLikeASystemOne() {
        // The exception is by exact path: a root-owned, admin-writable directory elsewhere gets none.
        var fs = userInstall();
        fs.put(HOME, dir(ROOT, ADMIN, MODE_775));

        assertThrows(SecurityException.class, () -> verify(fs, MacOsNativeLibraryLoader.userPath(HOME), USER_OWNERS));
    }

    @Test
    void aSymbolicLinkedDirectory_IsRefused() {
        var fs = userInstall();
        fs.put(HOME + "/.hkdfguard", new UnixFileStatus(USER, STAFF, MODE_755, UnixFileType.SYMBOLIC_LINK));

        var ex = assertThrows(SecurityException.class, () -> verify(fs, MacOsNativeLibraryLoader.userPath(HOME), USER_OWNERS));

        assertTrue(ex.getMessage().contains("is not a directory (it is a symbolic link)"));
    }

    @ParameterizedTest
    @CsvSource({"SYMBOLIC_LINK,symbolic link", "DIRECTORY,directory", "OTHER,special file"})
    void theLibraryItself_MustBeARegularFile(UnixFileType type, String described) {
        var fs = systemInstall();
        fs.put(MacOsNativeLibraryLoader.systemPath(), new UnixFileStatus(ROOT, WHEEL, MODE_644, type));

        var ex = assertThrows(SecurityException.class, () -> verify(fs, MacOsNativeLibraryLoader.systemPath(), SYSTEM_OWNERS));

        assertTrue(ex.getMessage().contains("(it is a " + described + ")"));
    }

    @Test
    void aDirectoryThatIsARegularFile_IsDescribedAsSuch() {
        var fs = systemInstall();
        fs.put("/Library/Application Support/HkdfGuard", file(ROOT, WHEEL, MODE_755));

        var ex = assertThrows(SecurityException.class, () -> verify(fs, MacOsNativeLibraryLoader.systemPath(), SYSTEM_OWNERS));

        assertTrue(ex.getMessage().contains("(it is a regular file)"));
    }

    // --- Code signature ---------------------------------------------------------------------------

    @Test
    void theCodeRequirement_PinsTheHkdfGuardTeam() {
        assertEquals("MFW3T8R8J3", MacOsNativeLibraryLoader.TEAM_ID);
        assertEquals("identifier \"libhkdfguard\" and anchor apple generic"
                        + " and certificate 1[field.1.2.840.113635.100.6.2.6] exists"
                        + " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
                        + " and certificate leaf[subject.OU] = \"MFW3T8R8J3\"",
                MacOsNativeLibraryLoader.CODE_REQUIREMENT);
    }

    @Test
    void verifySignature_PassesTheRequirement_AndAcceptsSuccess() {
        var checked = new String[1];

        MacOsNativeLibraryLoader.verifySignature("/x.dylib", (path, requirement) -> {
            checked[0] = requirement;
            return 0;
        });

        assertEquals(MacOsNativeLibraryLoader.CODE_REQUIREMENT, checked[0]);
    }

    @ParameterizedTest
    @ValueSource(ints = {-67050, -67062}) // errSecCSReqFailed: signed, but not by this team; errSecCSUnsigned
    void verifySignature_RefusesAnyFailure(int osStatus) {
        var ex = assertThrows(SecurityException.class, () -> MacOsNativeLibraryLoader.verifySignature("/x.dylib", (path, requirement) -> osStatus));

        assertTrue(ex.getMessage().contains("MFW3T8R8J3"));
        assertTrue(ex.getMessage().contains(Integer.toString(osStatus)));
    }

    // --- What dyld loads ------------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource(nullValues = "NULL", value = {"NULL", "''", "/opt/lib:/usr/local/lib"})
    void refuseShadowing_AllowsLoading_WhenNothingOnDyldLibraryPathHasTheLibrarysName(String searchPath) {
        assertDoesNotThrow(() -> MacOsNativeLibraryLoader.refuseShadowing(name -> name.equals("DYLD_LIBRARY_PATH") ? searchPath : null, path -> false));
    }

    @ParameterizedTest
    @org.junit.jupiter.params.provider.ValueSource(strings = {
            "DYLD_INSERT_LIBRARIES", "DYLD_FRAMEWORK_PATH", "DYLD_VERSIONED_LIBRARY_PATH", "DYLD_VERSIONED_FRAMEWORK_PATH", "DYLD_IMAGE_SUFFIX"})
    void refuseShadowing_Refuses_WhenADyldVariableThatInjectsOrSubstitutesCodeIsSet(String variable) {
        var ex = assertThrows(SecurityException.class, () ->
                MacOsNativeLibraryLoader.refuseShadowing(name -> name.equals(variable) ? "/tmp/inject.dylib" : null, path -> false));

        assertTrue(ex.getMessage().contains(variable));
        assertTrue(MacOsNativeLibraryLoader.REFUSED_DYLD_VARIABLES.contains(variable));
        // Set but empty is the same as unset.
        assertDoesNotThrow(() -> MacOsNativeLibraryLoader.refuseShadowing(name -> name.equals(variable) ? "" : null, path -> false));
    }

    @ParameterizedTest
    @CsvSource({
            "/tmp/decoy,/tmp/decoy/libhkdfguard.dylib",
            "/opt/lib:/tmp/decoy/:/usr/local/lib,/tmp/decoy/libhkdfguard.dylib", // any entry; a trailing slash is fine
    })
    void refuseShadowing_Refuses_WhenADyldLibraryPathDirectoryHoldsALibraryOfTheSameName(String searchPath, String decoy) {
        var ex = assertThrows(SecurityException.class, () ->
                MacOsNativeLibraryLoader.refuseShadowing(name -> name.equals("DYLD_LIBRARY_PATH") ? searchPath : null, decoy::equals));

        assertTrue(ex.getMessage().contains(decoy));
        assertTrue(ex.getMessage().contains("DYLD_LIBRARY_PATH"));
    }

    @Test
    void refuseShadowing_ConsultsOnlyTheDyldVariablesItChecks() {
        var asked = new ArrayList<String>();

        MacOsNativeLibraryLoader.refuseShadowing(name -> {
            asked.add(name);
            return null;
        }, path -> true);

        var expected = new ArrayList<>(MacOsNativeLibraryLoader.REFUSED_DYLD_VARIABLES);
        expected.add("DYLD_LIBRARY_PATH");
        assertEquals(expected, asked);
    }

    @Test
    void verifyLoadedImage_AcceptsTheVerifiedPath() {
        assertDoesNotThrow(() -> MacOsNativeLibraryLoader.verifyLoadedImage(MacOsNativeLibraryLoader.systemPath(), MacOsNativeLibraryLoader.systemPath()));
    }

    @Test
    void verifyLoadedImage_Refuses_WhenDyldLoadedAnotherFile() {
        var ex = assertThrows(SecurityException.class, () ->
                MacOsNativeLibraryLoader.verifyLoadedImage(MacOsNativeLibraryLoader.systemPath(), "/tmp/decoy/libhkdfguard.dylib"));

        assertTrue(ex.getMessage().contains("/tmp/decoy/libhkdfguard.dylib"));
        assertTrue(ex.getMessage().contains(MacOsNativeLibraryLoader.systemPath()));
        assertTrue(ex.getMessage().contains("unloaded"));
    }

    @Test
    void verifyLoadedImage_Refuses_WhenTheLoadedFileHasNoProbeExport() {
        var ex = assertThrows(SecurityException.class, () ->
                MacOsNativeLibraryLoader.verifyLoadedImage(MacOsNativeLibraryLoader.systemPath(), null));

        assertTrue(ex.getMessage().contains(MacOsNativeLibraryLoader.PROBE_EXPORT));
    }

    @Test
    void theProbeExport_IsOneTheBindingCalls() {
        assertEquals("hkdfguard_wrap_dek", MacOsNativeLibraryLoader.PROBE_EXPORT);
    }
}
