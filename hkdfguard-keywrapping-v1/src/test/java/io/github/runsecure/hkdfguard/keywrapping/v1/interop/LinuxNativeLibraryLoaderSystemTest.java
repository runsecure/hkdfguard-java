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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
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

    @Test
    void theInstalledLibrary_IsAKnownReleaseInATrustedLocation() throws IOException, NoSuchAlgorithmException {
        var path = NativeTestEnvironment.assumeLinuxLibraryInstalled();

        assertEquals(path, resolve(path));
        var hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(Path.of(path))));
        LinuxNativeLibraryLoader.verifyContent(path, p -> hash, LinuxNativeLibraryLoader.KNOWN_RELEASES);
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
