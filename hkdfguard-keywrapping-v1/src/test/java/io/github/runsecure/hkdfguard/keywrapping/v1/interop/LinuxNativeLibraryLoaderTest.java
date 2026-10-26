package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.keywrapping.v1.NativeLibraryNotFoundException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.attribute.PosixFilePermission;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The Linux loader's decisions - where the library is, whether every path to it and to its
 * dependencies can be trusted, and whether the dynamic linker's environment could substitute
 * anything - checked against simulated filesystems, so they run on every platform. LinuxNativeLibraryLoaderSystemTest runs the same checks against the real
 * filesystem and the installed package. Test names follow the .NET port's
 * LinuxNativeLibraryLoaderTests.
 */
class LinuxNativeLibraryLoaderTest {
    private static final long ROOT = 0;
    private static final long USER = 1000;

    private static final Set<PosixFilePermission> MODE_755 = UnixFileStatus.permissionsFromMode(0755);
    private static final Set<PosixFilePermission> MODE_775 = UnixFileStatus.permissionsFromMode(0775);
    // The sticky bit isn't a permission bit; /tmp is refused for being world-writable either way.
    private static final Set<PosixFilePermission> MODE_1777 = UnixFileStatus.permissionsFromMode(0777);
    private static final Set<PosixFilePermission> MODE_644 = UnixFileStatus.permissionsFromMode(0644);
    private static final Set<PosixFilePermission> MODE_664 = UnixFileStatus.permissionsFromMode(0664);
    private static final Set<PosixFilePermission> MODE_777 = UnixFileStatus.permissionsFromMode(0777);

    private static final String LIB_DIR = "/usr/lib/x86_64-linux-gnu";
    private static final String LIBRARY = LIB_DIR + "/libhkdfguard.so.1";
    private static final String ESYS = LIB_DIR + "/libtss2-esys.so.0.0.1";

    /** A simulated filesystem: what lstat sees, and what each symbolic link holds. */
    private static final class FileSystem {
        final Map<String, UnixFileStatus> entries = new HashMap<>();
        final Map<String, String> links = new HashMap<>();

        FileSystem dir(String path) {
            return dir(path, ROOT, MODE_755);
        }

        FileSystem dir(String path, long owner) {
            return dir(path, owner, MODE_755);
        }

        FileSystem dir(String path, long owner, Set<PosixFilePermission> mode) {
            entries.put(path, new UnixFileStatus(owner, owner, mode, UnixFileType.DIRECTORY));
            return this;
        }

        FileSystem file(String path) {
            return file(path, ROOT);
        }

        FileSystem file(String path, long owner) {
            entries.put(path, new UnixFileStatus(owner, owner, MODE_644, UnixFileType.REGULAR_FILE));
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

        void setPermissions(String path, Set<PosixFilePermission> mode) {
            var status = entries.get(path);
            entries.put(path, new UnixFileStatus(status.ownerId(), status.groupId(), mode, status.type()));
        }

        UnixFileStatus status(String path) {
            return entries.get(path);
        }

        String readLink(String path) {
            return links.get(path);
        }

        String resolve(String path) {
            return resolve(path, UnixFileType.REGULAR_FILE, false);
        }

        String resolve(String path, UnixFileType type) {
            return resolve(path, type, false);
        }

        String resolve(String path, UnixFileType type, boolean allowMissing) {
            return LinuxNativeLibraryLoader.resolveTrusted(path, type, this::status, this::readLink, allowMissing);
        }
    }

    // A standard Debian/Ubuntu host with merged /usr: /lib is a root-owned link to usr/lib.
    private static FileSystem standardHost() {
        return new FileSystem()
                .dir("/").dir("/usr").dir("/usr/lib").dir(LIB_DIR).dir("/usr/lib64").dir("/opt")
                .link("/lib", "usr/lib")
                .link("/lib64", "usr/lib64")
                .file(LIBRARY)
                .link(LIB_DIR + "/HkdfGuard.Kms.Linux.v1.so", "libhkdfguard.so.1")
                .link(LIB_DIR + "/libtss2-esys.so.0", "libtss2-esys.so.0.0.1")
                .file(ESYS)
                .file(LIB_DIR + "/libc.so.6")
                .dir("/home").dir("/home/dev", USER).dir("/home/dev/lib", USER).file("/home/dev/lib/libtss2-esys.so.0", USER)
                .dir("/tmp", ROOT, MODE_1777);
    }

    // --- Platform and location ------------------------------------------------------------------

    @Test
    void candidatePaths_AreThePackagesInstallLocations_ForEachArchitecture() {
        assertEquals(List.of("/usr/lib/x86_64-linux-gnu/libhkdfguard.so.1", "/usr/lib64/libhkdfguard.so.1"),
                LinuxNativeLibraryLoader.candidatePaths(CpuArchitecture.X64));
        assertEquals(List.of("/usr/lib/aarch64-linux-gnu/libhkdfguard.so.1", "/usr/lib64/libhkdfguard.so.1"),
                LinuxNativeLibraryLoader.candidatePaths(CpuArchitecture.ARM64));
    }

    @ParameterizedTest
    @EnumSource(value = CpuArchitecture.class, names = {"X86", "ARM", "OTHER"})
    void candidatePaths_RefuseEveryOtherArchitecture(CpuArchitecture architecture) {
        var ex = assertThrows(UnsupportedOperationException.class, () -> LinuxNativeLibraryLoader.candidatePaths(architecture));

        assertTrue(ex.getMessage().contains(architecture.toString()));
    }

    private static final int PRESENT = 0;
    private static final int ENOENT = 2;
    private static final int EACCES = 13;
    private static final int ENOTDIR = 20;

    private static final List<String> CANDIDATES = LinuxNativeLibraryLoader.candidatePaths(CpuArchitecture.X64);

    @Test
    void choosePath_PrefersTheMultiarchDirectory() {
        assertEquals(CANDIDATES.get(0), LinuxNativeLibraryLoader.choosePath(CANDIDATES, p -> PRESENT));
    }

    @ParameterizedTest
    @ValueSource(ints = {ENOENT, ENOTDIR})
    void choosePath_UsesLib64_OnlyWhenThereIsNothingInTheMultiarchDirectory(int errno) {
        assertEquals(CANDIDATES.get(1), LinuxNativeLibraryLoader.choosePath(CANDIDATES, p -> p.equals(CANDIDATES.get(0)) ? errno : PRESENT));
    }

    @Test
    void choosePath_WhenALocationCannotBeExamined_RefusesInsteadOfFallingBack() {
        var asked = new ArrayList<String>();
        var ex = assertThrows(SecurityException.class, () -> LinuxNativeLibraryLoader.choosePath(CANDIDATES, p -> {
            asked.add(p);
            return EACCES;
        }));

        assertEquals(List.of(CANDIDATES.get(0)), asked);
        assertTrue(ex.getMessage().contains("errno 13"));
    }

    @Test
    void choosePath_WithNothingInstalled_ThrowsNamingThePackageAndEveryLocation() {
        var ex = assertThrows(NativeLibraryNotFoundException.class, () -> LinuxNativeLibraryLoader.choosePath(CANDIDATES, p -> ENOENT));

        assertTrue(ex.getMessage().contains("libhkdfguard1"));
        assertTrue(ex.getMessage().contains(CANDIDATES.get(0)));
        assertTrue(ex.getMessage().contains(CANDIDATES.get(1)));
    }

    // --- Path integrity -------------------------------------------------------------------------

    @Test
    void aStandardInstall_ResolvesToItself() {
        assertEquals(LIBRARY, standardHost().resolve(LIBRARY));
    }

    @Test
    void aRootOwnedLink_IsFollowed_AndItsTargetChecked() {
        var fs = standardHost();

        assertEquals(ESYS, fs.resolve("/lib/x86_64-linux-gnu/libtss2-esys.so.0"));
        assertEquals(LIBRARY, fs.resolve(LIB_DIR + "/HkdfGuard.Kms.Linux.v1.so"));
        assertEquals(LIB_DIR, fs.resolve("/lib/x86_64-linux-gnu/", UnixFileType.DIRECTORY));
    }

    @Test
    void dotDot_IsResolvedAgainstTheRealDirectory_NotTheLinkThatLedThere() {
        // /opt/app -> ../usr/lib: "/opt/app/.." is /usr, not /opt.
        var fs = standardHost().link("/opt/app", "../usr/lib");

        assertEquals(LIBRARY, fs.resolve("/opt/app/x86_64-linux-gnu/libhkdfguard.so.1"));
        assertEquals("/usr", fs.resolve("/opt/app/..", UnixFileType.DIRECTORY));
        assertEquals("/", fs.resolve("/..", UnixFileType.DIRECTORY));
        assertEquals(LIBRARY, fs.resolve("/usr/./lib/x86_64-linux-gnu//libhkdfguard.so.1"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"usr/lib/x86_64-linux-gnu/libhkdfguard.so.1", "./libhkdfguard.so.1", ""})
    void aRelativePath_IsRefused(String path) {
        var ex = assertThrows(SecurityException.class, () -> standardHost().resolve(path));

        assertTrue(ex.getMessage().contains("not an absolute path"));
    }

    @Test
    void aFileOwnedByAUser_IsRefused() {
        var fs = standardHost().file(LIBRARY, USER);

        var ex = assertThrows(SecurityException.class, () -> fs.resolve(LIBRARY));
        assertTrue(ex.getMessage().contains("uid 1000"));
    }

    @Test
    void aDirectoryOwnedByAUser_IsRefused_WhereverItIsOnThePath() {
        var fs = standardHost().dir("/usr/lib", USER);

        var ex = assertThrows(SecurityException.class, () -> fs.resolve(LIBRARY));
        assertTrue(ex.getMessage().contains("'/usr/lib'"));
    }

    @ParameterizedTest
    @CsvSource({
            "/, 775",
            "/usr, 775",
            LIB_DIR + ", 775",
            LIB_DIR + ", 777",
            LIBRARY + ", 664",
    })
    void anythingWritableByGroupOrOthers_IsRefused_EvenWhenRootOwned(String path, String mode) {
        var fs = standardHost();
        fs.setPermissions(path, switch (mode) {
            case "775" -> MODE_775;
            case "777" -> MODE_777;
            default -> MODE_664;
        });

        var ex = assertThrows(SecurityException.class, () -> fs.resolve(LIBRARY));
        assertTrue(ex.getMessage().contains("'" + path + "' is writable"), ex.getMessage());
    }

    @Test
    void aStickyWorldWritableDirectory_IsRefused() {
        var fs = standardHost().file("/tmp/libtss2-esys.so.0");

        assertThrows(SecurityException.class, () -> fs.resolve("/tmp/libtss2-esys.so.0"));
    }

    @Test
    void aLinkOwnedByAUser_IsRefused_EvenWhenItPointsSomewhereTrusted() {
        var fs = standardHost().link("/opt/lib", "/usr/lib", USER);

        var ex = assertThrows(SecurityException.class, () -> fs.resolve("/opt/lib/x86_64-linux-gnu/libhkdfguard.so.1"));
        assertTrue(ex.getMessage().contains("symbolic link owned by uid 1000"));
    }

    @Test
    void aRootOwnedLink_IntoAUsersDirectory_IsRefused() {
        var fs = standardHost().link("/opt/lib", "/home/dev/lib");

        var ex = assertThrows(SecurityException.class, () -> fs.resolve("/opt/lib/libtss2-esys.so.0"));
        assertTrue(ex.getMessage().contains("'/home/dev'"));
    }

    @Test
    void aLinkLoop_IsRefused() {
        var fs = standardHost().link("/opt/a", "/opt/b").link("/opt/b", "/opt/a");

        var ex = assertThrows(SecurityException.class, () -> fs.resolve("/opt/a/x"));
        assertTrue(ex.getMessage().contains(LinuxNativeLibraryLoader.MAX_SYMBOLIC_LINKS + " symbolic links"));
    }

    @Test
    void aLinkThatCannotBeRead_IsRefused() {
        var fs = standardHost();
        fs.entries.put("/opt/broken", new UnixFileStatus(ROOT, ROOT, MODE_777, UnixFileType.SYMBOLIC_LINK));

        var ex = assertThrows(SecurityException.class, () -> fs.resolve("/opt/broken/x"));
        assertTrue(ex.getMessage().contains("could not be read"));
    }

    @Test
    void aMissingPath_IsRefused_UnlessMissingIsAllowed() {
        var fs = standardHost();

        var ex = assertThrows(SecurityException.class, () -> fs.resolve(LIB_DIR + "/nothing.so"));
        assertTrue(ex.getMessage().contains("does not exist"));
        assertNull(fs.resolve(LIB_DIR + "/nothing.so", UnixFileType.REGULAR_FILE, true));
        assertNull(fs.resolve("/opt/not/yet/created", UnixFileType.DIRECTORY, true));
    }

    @Test
    void aMissingPath_UnderAnUntrustedDirectory_IsStillRefused() {
        // Something missing is only harmless if nobody but root could create it.
        var fs = standardHost();

        assertThrows(SecurityException.class, () -> fs.resolve("/home/dev/lib/nothing.so", UnixFileType.REGULAR_FILE, true));
    }

    @Test
    void theWrongKindOfObject_IsRefused() {
        var fs = standardHost();
        fs.entries.put("/opt/fifo", new UnixFileStatus(ROOT, ROOT, MODE_644, UnixFileType.OTHER));

        assertTrue(assertThrows(SecurityException.class, () -> fs.resolve(LIB_DIR)).getMessage().contains("is a directory, not a regular file"));
        assertTrue(assertThrows(SecurityException.class, () -> fs.resolve(LIBRARY, UnixFileType.DIRECTORY)).getMessage().contains("is a regular file, not a directory"));
        assertTrue(assertThrows(SecurityException.class, () -> fs.resolve("/opt/fifo")).getMessage().contains("is a special file"));
    }

    @Test
    void aPathThroughAFile_IsRefused() {
        var ex = assertThrows(SecurityException.class, () -> standardHost().resolve(LIBRARY + "/x"));

        assertTrue(ex.getMessage().contains("not a directory"));
    }

    @Test
    void anUnexaminableRoot_IsRefused() {
        var ex = assertThrows(SecurityException.class,
                () -> LinuxNativeLibraryLoader.resolveTrusted(LIBRARY, UnixFileType.REGULAR_FILE, p -> null, p -> null));

        assertTrue(ex.getMessage().contains("'/'"));
    }

    @ParameterizedTest
    @CsvSource({"/, /", "/usr, /", "/usr/lib, /usr"})
    void parentOf_WalksUpToRoot(String path, String parent) {
        assertEquals(parent, LinuxNativeLibraryLoader.parentOf(path));
    }

    // --- Environment ----------------------------------------------------------------------------

    private static byte[] environBlock(String... entries) {
        return (String.join("\0", entries) + "\0").getBytes(StandardCharsets.UTF_8);
    }

    @Test
    void readEnvironment_CollectsTheInitialAndCurrentValues_OfTheLinkersVariablesOnly() {
        var current = Map.of("LD_LIBRARY_PATH", "/now", "LD_PRELOAD", "/same.so");
        var values = LinuxNativeLibraryLoader.readEnvironment(current::get,
                environBlock("PATH=/usr/bin", "LD_LIBRARY_PATH=/at/exec", "LD_PRELOAD=/same.so", "LD_AUDIT=/a.so=b", "=junk", "NOEQUALS"));

        assertEquals(List.of("/at/exec", "/now"), values.get("LD_LIBRARY_PATH"));
        assertEquals(List.of("/same.so"), values.get("LD_PRELOAD"));
        assertEquals(List.of("/a.so=b"), values.get("LD_AUDIT"));
        assertEquals(3, values.size());
    }

    @Test
    void readEnvironment_WithoutProcEnviron_UsesTheCurrentEnvironment() {
        var values = LinuxNativeLibraryLoader.readEnvironment(n -> n.equals("LD_PRELOAD") ? "x.so" : null, null);

        assertEquals(List.of("x.so"), values.get("LD_PRELOAD"));
        assertTrue(values.get("LD_LIBRARY_PATH").isEmpty());
    }

    private static void verifyEnvironment(FileSystem fs, String variable, String... values) {
        LinuxNativeLibraryLoader.verifyEnvironment(Map.of(variable, List.of(values)), (p, type) -> fs.resolve(p, type, true));
    }

    @Test
    void anUnsetEnvironment_Passes() {
        assertDoesNotThrow(() -> LinuxNativeLibraryLoader.verifyEnvironment(Map.of(), (p, type) -> {
            throw new IllegalStateException("nothing to resolve");
        }));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "",                                   // ignored by the dynamic linker
            "/usr/lib/x86_64-linux-gnu",
            "/lib/x86_64-linux-gnu:/usr/lib64",   // through root-owned links
            "/usr/lib;/usr/lib64",                // ';' separates too
            "/opt/not/installed/yet",             // missing, but only root could create it
    })
    void aLibraryPathOfRootControlledDirectories_Passes(String value) {
        assertDoesNotThrow(() -> verifyEnvironment(standardHost(), "LD_LIBRARY_PATH", value));
    }

    @ParameterizedTest
    @ValueSource(strings = {"/home/dev/lib", "/usr/lib:/home/dev/lib", "/tmp", "/home/dev/lib/not-yet"})
    void aLibraryPathWithADirectoryOthersCanWrite_IsRefused(String value) {
        var ex = assertThrows(SecurityException.class, () -> verifyEnvironment(standardHost(), "LD_LIBRARY_PATH", value));

        assertTrue(ex.getMessage().contains("LD_LIBRARY_PATH"));
        assertTrue(ex.getMessage().contains("Remove it"));
    }

    @ParameterizedTest
    @ValueSource(strings = {":/usr/lib", "/usr/lib:", "/usr/lib::/usr/lib64"})
    void aLibraryPathWithAnEmptyEntry_IsRefused_AsTheWorkingDirectory(String value) {
        var ex = assertThrows(SecurityException.class, () -> verifyEnvironment(standardHost(), "LD_LIBRARY_PATH", value));

        assertTrue(ex.getMessage().contains("working directory"));
    }

    @ParameterizedTest
    @CsvSource({
            "lib, relative",
            "./lib, relative",
            "$ORIGIN/lib, dynamic string token",
            "/usr/${LIB}, dynamic string token",
    })
    void aLibraryPathThatCantBeCheckedInAdvance_IsRefused(String value, String reason) {
        var ex = assertThrows(SecurityException.class, () -> verifyEnvironment(standardHost(), "LD_LIBRARY_PATH", value));

        assertTrue(ex.getMessage().contains(reason));
    }

    @Test
    void everyValueTheVariableHasHad_IsChecked() {
        // A clean current value must not hide what the process started with.
        assertThrows(SecurityException.class, () -> verifyEnvironment(standardHost(), "LD_LIBRARY_PATH", "/usr/lib", "/home/dev/lib"));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "LD_PRELOAD|libjemalloc.so.2",                                    // a bare name: found by the checked search
            "LD_PRELOAD|/usr/lib/x86_64-linux-gnu/libc.so.6",
            "LD_PRELOAD|libjemalloc.so.2 /lib/x86_64-linux-gnu/libc.so.6",
            "LD_PRELOAD|'   '",
            "LD_AUDIT|/usr/lib/x86_64-linux-gnu/libc.so.6:libaudit.so",
    })
    void preloadingOrAuditingFromRootControlledLocations_Passes(String variable, String value) {
        assertDoesNotThrow(() -> verifyEnvironment(standardHost(), variable, value));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "LD_PRELOAD|/home/dev/lib/libtss2-esys.so.0",
            "LD_PRELOAD|libjemalloc.so.2 /home/dev/lib/libtss2-esys.so.0",
            "LD_PRELOAD|libjemalloc.so.2:/home/dev/lib/libtss2-esys.so.0",
            "LD_PRELOAD|./evil.so",
            "LD_PRELOAD|$LIB/evil.so",
            "LD_AUDIT|/home/dev/lib/libtss2-esys.so.0",
            "LD_AUDIT|lib/evil.so",
    })
    void preloadingOrAuditingFromAnywhereElse_IsRefused(String variable, String value) {
        var ex = assertThrows(SecurityException.class, () -> verifyEnvironment(standardHost(), variable, value));

        assertTrue(ex.getMessage().contains(variable));
    }

    @Test
    void aLocationThatCannotBeExamined_IsRefused() {
        var ex = assertThrows(SecurityException.class, () -> LinuxNativeLibraryLoader.verifyEnvironment(
                Map.of("LD_LIBRARY_PATH", List.of("/srv/lib")),
                (p, type) -> {
                    throw new UncheckedIOException(new IOException("statx('/srv') failed with errno 13."));
                }));

        assertTrue(ex.getMessage().contains("errno 13"));
        assertInstanceOf(UncheckedIOException.class, ex.getCause());
    }

    // --- What was loaded ------------------------------------------------------------------------

    @Test
    void verifyLoadedImage_Accepts_TheVerifiedPath() {
        assertDoesNotThrow(() -> LinuxNativeLibraryLoader.verifyLoadedImage(LIBRARY, LIBRARY));
    }

    @Test
    void verifyLoadedImage_Refuses_AnotherFile() {
        var ex = assertThrows(SecurityException.class, () -> LinuxNativeLibraryLoader.verifyLoadedImage(LIBRARY, "/usr/lib64/libhkdfguard.so.1"));

        assertTrue(ex.getMessage().contains("/usr/lib64/libhkdfguard.so.1"));
    }

    @Test
    void verifyLoadedImage_Refuses_WhenTheLoadedFileHasNoProbeExport() {
        var ex = assertThrows(SecurityException.class, () -> LinuxNativeLibraryLoader.verifyLoadedImage(LIBRARY, null));

        assertTrue(ex.getMessage().contains(LinuxNativeLibraryLoader.PROBE_EXPORT));
    }

    @Test
    void theProbeExport_IsOneTheBindingCalls() {
        assertEquals("hkdfguard_wrap_dek", LinuxNativeLibraryLoader.PROBE_EXPORT);
    }

    // The installed library's closure, as ldd reports it on Ubuntu 24.04.
    private static final Map<String, List<String>> NEEDED = Map.of(
            LIBRARY, List.of("libtss2-esys.so.0", "libgcc_s.so.1", "libc.so.6"),
            ESYS, List.of("libtss2-mu.so.0", "libcrypto.so.3", "libc.so.6"),
            LIB_DIR + "/libtss2-mu.so.0.0.1", List.of("libc.so.6"),
            LIB_DIR + "/libcrypto.so.3", List.of("libc.so.6"),
            LIB_DIR + "/libgcc_s.so.1", List.of("libc.so.6"),
            LIB_DIR + "/libc.so.6", List.of("ld-linux-x86-64.so.2"),
            LIB_DIR + "/ld-linux-x86-64.so.2", List.of());

    private static final Map<String, String> LOADED = Map.of(
            "libtss2-esys.so.0", "/lib/x86_64-linux-gnu/libtss2-esys.so.0",
            "libtss2-mu.so.0", "/lib/x86_64-linux-gnu/libtss2-mu.so.0",
            "libcrypto.so.3", "/lib/x86_64-linux-gnu/libcrypto.so.3",
            "libgcc_s.so.1", "/lib/x86_64-linux-gnu/libgcc_s.so.1",
            "libc.so.6", "/lib/x86_64-linux-gnu/libc.so.6",
            "ld-linux-x86-64.so.2", "/lib64/ld-linux-x86-64.so.2");

    private static FileSystem hostWithClosure() {
        return standardHost()
                .link(LIB_DIR + "/libtss2-mu.so.0", "libtss2-mu.so.0.0.1").file(LIB_DIR + "/libtss2-mu.so.0.0.1")
                .file(LIB_DIR + "/libcrypto.so.3").file(LIB_DIR + "/libgcc_s.so.1")
                .link("/usr/lib64/ld-linux-x86-64.so.2", "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2").file(LIB_DIR + "/ld-linux-x86-64.so.2");
    }

    private static void verifyDependencies(FileSystem fs, Map<String, String> loaded) {
        verifyDependencies(fs, loaded, null);
    }

    private static void verifyDependencies(FileSystem fs, Map<String, String> loaded, List<String> read) {
        LinuxNativeLibraryLoader.verifyDependencies(
                LIBRARY,
                file -> {
                    if (read != null)
                        read.add(file);
                    return NEEDED.get(file);
                },
                loaded::get,
                fs::resolve);
    }

    @Test
    void aTrustedDependencyClosure_Passes_AndEveryFileInItIsRead_Once() {
        var read = new ArrayList<String>();
        verifyDependencies(hostWithClosure(), LOADED, read);

        assertEquals(NEEDED.keySet().stream().sorted().toList(), read.stream().sorted().toList());
    }

    @Test
    void aDirectDependency_LoadedFromAUsersDirectory_IsRefused() {
        var loaded = new HashMap<>(LOADED);
        loaded.put("libtss2-esys.so.0", "/home/dev/lib/libtss2-esys.so.0");

        var ex = assertThrows(SecurityException.class, () -> verifyDependencies(hostWithClosure(), loaded));
        assertTrue(ex.getMessage().contains("'libtss2-esys.so.0'"));
        assertTrue(ex.getMessage().contains(LIBRARY));
    }

    @Test
    void aTransitiveDependency_LoadedFromAnUntrustedDirectory_IsRefused() {
        var fs = hostWithClosure().file("/tmp/libcrypto.so.3");
        var loaded = new HashMap<>(LOADED);
        loaded.put("libcrypto.so.3", "/tmp/libcrypto.so.3");

        var ex = assertThrows(SecurityException.class, () -> verifyDependencies(fs, loaded));
        assertTrue(ex.getMessage().contains("'libcrypto.so.3' (needed by '" + ESYS + "')"), ex.getMessage());
    }

    @Test
    void aDependencyNothingAnswersTo_IsRefused() {
        var loaded = new HashMap<>(LOADED);
        loaded.remove("libgcc_s.so.1");

        var ex = assertThrows(SecurityException.class, () -> verifyDependencies(hostWithClosure(), loaded));
        assertTrue(ex.getMessage().contains("libgcc_s.so.1"));
    }

    @Test
    void parseListing_ReturnsEveryFile_SkippingTheVdso() {
        var output = "\tlinux-vdso.so.1 (0x00007ffd2a5f2000)\n"
                + "\tlibtss2-esys.so.0 => /lib/x86_64-linux-gnu/libtss2-esys.so.0 (0x00007f1c2a000000)\n"
                + "\t/usr/lib/libpreloaded.so (0x00007f1c29e00000)\n"
                + "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f1c29c00000)\n"
                + "\t/lib64/ld-linux-x86-64.so.2 (0x00007f1c2a200000)\n";

        assertEquals(List.of("/lib/x86_64-linux-gnu/libtss2-esys.so.0", "/usr/lib/libpreloaded.so", "/lib/x86_64-linux-gnu/libc.so.6",
                "/lib64/ld-linux-x86-64.so.2"), LinuxNativeLibraryLoader.parseListing("lib", output));
    }

    @Test
    void parseListing_ANameItCannotFind_OrALineItCannotRead_IsRefused() {
        assertListingRefused("\tlibmissing.so.1 => not found\n", "can't find 'libmissing.so.1'");
        assertListingRefused("\tstatically linked\n", "doesn't understand");
        assertListingRefused("\tlibx.so => relative/libx.so (0x1000)\n", "not an absolute path");
    }

    private static void assertListingRefused(String output, String reason) {
        var ex = assertThrows(SecurityException.class, () -> LinuxNativeLibraryLoader.parseListing("lib", output));
        assertTrue(ex.getMessage().contains(reason), ex.getMessage());
    }

    @Test
    void listingEnvironment_IsOnlyTheStartupLibraryPathAndPreload() {
        var initial = "HOME=/root\0LD_LIBRARY_PATH=/opt/lib\0LD_AUDIT=/opt/audit.so\0PATH=/usr/bin\0LD_PRELOAD=/opt/pre.so\0".getBytes(StandardCharsets.UTF_8);

        assertEquals(Map.of("LD_LIBRARY_PATH", "/opt/lib", "LD_PRELOAD", "/opt/pre.so"), LinuxNativeLibraryLoader.listingEnvironment(initial));
        assertEquals(Map.of(), LinuxNativeLibraryLoader.listingEnvironment(null));
        assertEquals(Map.of(), LinuxNativeLibraryLoader.listingEnvironment(new byte[0]));
        // Neither a longer name that starts the same nor a bare name without '=' counts.
        assertEquals(Map.of(), LinuxNativeLibraryLoader.listingEnvironment("LD_PRELOAD_X=/a\0LD_PRELOAD\0".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void verifyListing_RefusesTheFirstUntrustedPath() {
        UnaryOperator<String> trusted = p -> {
            if (p.startsWith("/tmp/"))
                throw new SecurityException("'" + p + "' is writable by others.");
            return p;
        };

        assertDoesNotThrow(() -> LinuxNativeLibraryLoader.verifyListing("lib", List.of("/lib/libc.so.6", "/lib64/ld-linux-x86-64.so.2"), trusted));
        var ex = assertThrows(SecurityException.class,
                () -> LinuxNativeLibraryLoader.verifyListing("lib", List.of("/lib/libc.so.6", "/tmp/libtss2-esys.so.0", "/tmp/second.so"), trusted));
        assertTrue(ex.getMessage().contains("/tmp/libtss2-esys.so.0"), ex.getMessage());
        assertTrue(ex.getMessage().contains("nothing was loaded"), ex.getMessage());
        assertFalse(ex.getMessage().contains("/tmp/second.so"), ex.getMessage());
    }

    @Test
    void aDependencyThatCannotBeExamined_IsRefused() {
        var ex = assertThrows(SecurityException.class, () -> LinuxNativeLibraryLoader.verifyDependencies(
                LIBRARY, f -> List.of("libc.so.6"), n -> "/lib/x86_64-linux-gnu/libc.so.6", p -> {
                    throw new UncheckedIOException(new IOException("statx failed with errno 13."));
                }));

        assertInstanceOf(UncheckedIOException.class, ex.getCause());
    }
}
