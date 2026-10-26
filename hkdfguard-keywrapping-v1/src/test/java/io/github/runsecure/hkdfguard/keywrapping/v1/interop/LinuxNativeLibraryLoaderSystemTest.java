package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.keywrapping.v1.NativeLibraryNotFoundException;
import java.io.IOException;
import java.lang.foreign.Linker;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.List;
import java.util.Map;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

/**
 * The Linux loader's checks against this machine's real filesystem and dynamic linker, and the
 * installed libhkdfguard1 package where there is one. Skipped off Linux. Test names follow the .NET
 * port's LinuxNativeLibraryLoaderSystemTests.
 */
@EnabledOnOs(value = OS.LINUX, disabledReason = "Linux only.")
class LinuxNativeLibraryLoaderSystemTest {
    private static String resolve(String path) {
        return resolve(path, UnixFileType.REGULAR_FILE, false);
    }

    private static String resolve(String path, UnixFileType type, boolean allowMissing) {
        return LinuxNativeLibraryLoader.resolveTrusted(path, type, LinuxNative::statusOrNull, LinuxNative::readLink, allowMissing);
    }

    @Test
    void theRootDirectory_AndThisProcesssLibc_AreTrusted() {
        assertEquals("/", resolve("/", UnixFileType.DIRECTORY, false));

        var libc = LinuxNative.loadedPath("libc.so.6");
        assertNotNull(libc);
        assertTrue(resolve(libc).startsWith("/"));
    }

    @Test
    void theRootAndSystemLibraryDirectories_AreTrusted() {
        // Go's TestLinuxSystem_TheRootAndSystemLibraryDirectories_AreTrusted.
        for (var directory : List.of("/", "/usr/lib"))
            assertEquals(directory, resolve(directory, UnixFileType.DIRECTORY, false));
    }

    @Test
    void probeDistinguishesMissingFromPresent() {
        assertEquals(0, LinuxNative.probe("/"));
        assertEquals(2, LinuxNative.probe("/definitely/not/here")); // ENOENT
    }

    @Test
    void statusAndReadLink_DescribeThisUsersFiles() throws IOException {
        var directory = Files.createTempDirectory("hkdfguard-status-");
        var file = directory.resolve("file");
        var link = directory.resolve("link");
        try {
            Files.createFile(file, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-r-----")));
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r-----")); // whatever the umask
            Files.createSymbolicLink(link, Path.of("file"));
            var uid = ((Number) Files.getAttribute(directory, "unix:uid")).longValue();

            var status = LinuxNative.statusOrNull(file.toString());
            assertEquals(UnixFileType.REGULAR_FILE, status.type());
            assertEquals(uid, status.ownerId());
            assertEquals(PosixFilePermissions.fromString("rw-r-----"), status.permissions());

            var linkStatus = LinuxNative.statusOrNull(link.toString());
            assertEquals(UnixFileType.SYMBOLIC_LINK, linkStatus.type());
            assertEquals(uid, linkStatus.ownerId());
            assertEquals("file", LinuxNative.readLink(link.toString()));
            assertNull(LinuxNative.statusOrNull(directory.resolve("missing").toString()));

            // In a temporary directory - world-writable, or owned by this user - so the loader
            // refuses it, however it is reached.
            assertThrows(SecurityException.class, () -> resolve(file.toString()));
            assertThrows(SecurityException.class, () -> resolve(link.toString()));
        } finally {
            Files.deleteIfExists(link);
            Files.deleteIfExists(file);
            Files.delete(directory);
        }
    }

    @Test
    void aNameNothingIsLoadedUnder_HasNoLoadedPath() {
        assertNull(LinuxNative.loadedPath("libhkdfguard-never-loaded.so.0"));
    }

    @Test
    void aDirectoryThisUserCreated_IsNotTrusted_ForTheLibraryPath() throws IOException {
        // The attack this loader exists to stop: a directory the service's own user (or anyone)
        // can write, put on LD_LIBRARY_PATH so a dependency is found there first.
        var directory = Files.createTempDirectory("hkdfguard-ldpath-");
        try {
            var ex = assertThrows(SecurityException.class, () -> LinuxNativeLibraryLoader.verifyEnvironment(
                    Map.of("LD_LIBRARY_PATH", List.of(directory.toString())),
                    (p, type) -> resolve(p, type, true)));

            assertTrue(ex.getMessage().contains(directory.toString()), ex.getMessage());
        } finally {
            Files.delete(directory);
        }
    }

    @Test
    void theLinkersVariables_AreReadFromProcEnviron() {
        // Whatever this process started with, /proc/self/environ must be readable for the loader
        // to see it - and parse to the same three variables.
        var block = LinuxNative.readInitialEnvironment();
        assertNotNull(block);

        var values = LinuxNativeLibraryLoader.readEnvironment(n -> null, block);
        assertEquals(List.of("LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD"), values.keySet().stream().sorted().toList());
    }

    @Test
    void aSymbolicLink_IsReportedAsOne_AndReadExactlyAsStored() throws IOException {
        // Java-only: .NET reads link targets with the runtime's own API; here readlink is bound
        // directly, so check it against the real filesystem.
        var directory = Files.createTempDirectory("hkdfguard-link-");
        var link = directory.resolve("link");
        try {
            Files.createSymbolicLink(link, Path.of("../some/target.so"));

            assertEquals(UnixFileType.SYMBOLIC_LINK, LinuxNative.statusOrNull(link.toString()).type());
            assertEquals("../some/target.so", LinuxNative.readLink(link.toString()));
            assertNull(LinuxNative.readLink(directory.toString()));
            assertNull(LinuxNative.statusOrNull(directory.resolve("missing").toString()));
            assertEquals(2, LinuxNative.probe(directory.resolve("missing").toString())); // ENOENT
        } finally {
            Files.deleteIfExists(link);
            Files.delete(directory);
        }
    }

    @Test
    void thisProcesssLibc_PassesTheLoadedImageAndDependencyChecks() {
        // Java-only: the post-load checks (dladdr, DT_NEEDED parsing, dlinfo, path checks) against a
        // real loaded library, so they run on any Linux host, package or not.
        UnaryOperator<String> trusted = LinuxNativeLibraryLoaderSystemTest::resolve;
        var libc = trusted.apply(LinuxNative.loadedPath("libc.so.6"));
        var statx = Linker.nativeLinker().defaultLookup().find("statx").orElseThrow();

        LinuxNativeLibraryLoader.verifyLoadedImage(libc, trusted.apply(LinuxNative.imagePath(statx)));
        assertFalse(ElfDependencies.readNeeded(libc).isEmpty());
        LinuxNativeLibraryLoader.verifyDependencies(libc, ElfDependencies::readNeeded, LinuxNative::loadedPath, trusted);
    }

    @Test
    void withoutThePackage_LoadingReportsItIsNotInstalled() {
        // Java-only: where the package is absent, the real loader must say so, naming the package,
        // rather than fall back to any search.
        Assumptions.assumeTrue(NativeTestEnvironment.linuxInstalledPath() == null, "The libhkdfguard1 package is installed.");
        try {
            LinuxNativeLibraryLoader.candidatePaths(CpuArchitecture.current());
        } catch (UnsupportedOperationException e) {
            Assumptions.abort("No package is built for this architecture.");
        }

        var ex = assertThrows(NativeLibraryNotFoundException.class, LinuxNativeLibraryLoader::load);
        assertTrue(ex.getMessage().contains("libhkdfguard1"));
    }

    // The real dynamic linker in list mode, against files every Linux system has (Go's
    // linuxpreflight_linux_test.go).
    private static List<String> listingFor(String target, Map<String, String> environment) {
        var interpreter = ElfDependencies.readInterpreter(LinuxNativeLibraryLoader.SELF_EXECUTABLE);
        assertNotNull(interpreter);
        return LinuxNativeLibraryLoader.parseListing(target, LinuxNativeLibraryLoader.listDependencies(interpreter, target, environment));
    }

    private static String libcIn(List<String> paths) {
        var libc = paths.stream().filter(p -> Path.of(p).getFileName().toString().startsWith("libc.so")).findFirst().orElse(null);
        Assumptions.assumeTrue(libc != null, "No libc in /bin/sh's listing.");
        return libc;
    }

    @Test
    void theListingOfASystemBinary_NamesLibc_AndPassesThePathChecks() {
        var paths = listingFor("/bin/sh", Map.of());

        assertTrue(paths.stream().anyMatch(p -> Path.of(p).getFileName().toString().contains("libc.so")), paths.toString());
        LinuxNativeLibraryLoader.verifyListing("/bin/sh", paths, LinuxNativeLibraryLoaderSystemTest::resolve);
    }

    @Test
    void aDependencyFoundInAWritableFolder_IsRefusedBeforeAnythingLoads() throws IOException {
        // The real dynamic linker, told by LD_LIBRARY_PATH to look in a folder anyone can write,
        // finds a copy of libc there; the check refuses it whoever owns it, since the folder is 0777.
        var libc = libcIn(listingFor("/bin/sh", Map.of()));
        var folder = Files.createTempDirectory("hkdfguard-listing-");
        var planted = folder.resolve(Path.of(libc).getFileName());
        try {
            Files.setPosixFilePermissions(folder, PosixFilePermissions.fromString("rwxrwxrwx"));
            Files.copy(Path.of(libc), planted);
            Files.setPosixFilePermissions(planted, PosixFilePermissions.fromString("rwxr-xr-x"));

            var paths = listingFor("/bin/sh", Map.of("LD_LIBRARY_PATH", folder.toString()));
            assertTrue(paths.contains(planted.toString()), "the linker did not pick up the planted copy: " + paths);

            var ex = assertThrows(SecurityException.class,
                    () -> LinuxNativeLibraryLoader.verifyListing("/bin/sh", paths, LinuxNativeLibraryLoaderSystemTest::resolve));
            assertTrue(ex.getMessage().contains(planted.toString()), ex.getMessage());
            assertTrue(ex.getMessage().contains("nothing was loaded"), ex.getMessage());
        } finally {
            Files.deleteIfExists(planted);
            Files.delete(folder);
        }
    }

    @Test
    void aBareNamedPreload_IsListedWithTheFileItWasFoundIn() {
        // Java-only: the environment check skips bare-named LD_PRELOAD entries; the list run, given
        // the startup LD_PRELOAD, reports where each was found, so the path checks still see it.
        var libc = libcIn(listingFor("/bin/sh", Map.of()));
        var libm = Path.of(libc).resolveSibling("libm.so.6");
        Assumptions.assumeTrue(Files.exists(libm), "No libm.so.6 beside libc.");

        var paths = listingFor("/bin/sh", Map.of("LD_PRELOAD", "libm.so.6"));
        assertTrue(paths.stream().anyMatch(p -> Path.of(p).getFileName().toString().equals("libm.so.6")), paths.toString());
        LinuxNativeLibraryLoader.verifyListing("/bin/sh", paths, LinuxNativeLibraryLoaderSystemTest::resolve);
    }

    @Test
    void theListingOfAFileThatDoesNotExist_Fails() {
        var interpreter = ElfDependencies.readInterpreter(LinuxNativeLibraryLoader.SELF_EXECUTABLE);

        assertThrows(SecurityException.class, () -> LinuxNativeLibraryLoader.listDependencies(interpreter, "/nonexistent/libhkdfguard.so.1", Map.of()));
    }

    @Test
    void theListingOfASharedLibrary_NamesTheDynamicLinker() {
        // libhkdfguard.so.1 is a shared object, not an executable; list mode works on those too.
        var libc = libcIn(listingFor("/bin/sh", Map.of()));
        var paths = listingFor(libc, Map.of());

        assertTrue(paths.stream().anyMatch(p -> Path.of(p).getFileName().toString().contains("ld-linux")), libc + ": " + paths);
        LinuxNativeLibraryLoader.verifyListing(libc, paths, LinuxNativeLibraryLoaderSystemTest::resolve);
    }

    @Test
    void thisProcesssLibc_PassesTheWholePreLoadCheck() {
        // Java-only: verifyBeforeLoading end to end - PT_INTERP, its path checks, the list run
        // under this process's own startup environment, and the path checks on what it lists.
        var libc = resolve(LinuxNative.loadedPath("libc.so.6"));

        LinuxNativeLibraryLoader.verifyBeforeLoading(libc, LinuxNative.readInitialEnvironment(), LinuxNativeLibraryLoaderSystemTest::resolve);
    }

    @Test
    void theInstalledLibrary_IsInATrustedLocation() {
        var path = NativeTestEnvironment.assumeLinuxLibraryInstalled();

        assertEquals(path, resolve(path));
    }

    @Test
    void theInstalledLibrary_LoadsThroughTheVerifiedLoader_AndAnswersTheBinding() {
        var path = NativeTestEnvironment.assumeLinuxLibraryInstalled();

        var library = LinuxNativeLibraryLoader.load();
        assertNotNull(library);
        assertSame(library, LinuxNativeLibraryLoader.load()); // once per process

        // Through the binding: a wrap for a service nobody provisioned. Whatever this host's
        // providers say, the answer is a status code the binding can describe - never a
        // NativeLibraryNotFoundException from a by-name search.
        var binding = new LinuxHkdfGuardKmsLibrary();
        var result = binding.wrapDek("hkdfguard.loadertest.unprovisioned", new byte[32], new byte[512]);
        assertTrue(result.status() == AbstractHkdfGuardKmsLibrary.OK || binding.describeStatus(result.status()) != null,
                "undescribed status " + result.status());

        // And the export the binding calls came from the verified file.
        var export = LinuxNativeLibraryLoader.export(library, LinuxNativeLibraryLoader.PROBE_EXPORT);
        assertEquals(path, resolve(LinuxNative.imagePath(export)));

        // And every dependency the dynamic linker pulled in came from a trusted file (Go's
        // TestLinuxSystem_TheInstalledLibrary_LoadsThroughTheVerifiedLoader_AndItsDependenciesAreTrusted).
        LinuxNativeLibraryLoader.verifyDependencies(path, ElfDependencies::readNeeded, LinuxNative::loadedPath, LinuxNativeLibraryLoaderSystemTest::resolve);
    }
}
