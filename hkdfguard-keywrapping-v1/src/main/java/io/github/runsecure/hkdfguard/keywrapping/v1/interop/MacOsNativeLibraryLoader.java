package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import io.github.runsecure.hkdfguard.keywrapping.v1.NativeLibraryNotFoundException;
import java.lang.foreign.MemorySegment;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.ToIntBiFunction;
import java.util.function.ToIntFunction;

/**
 * Loads the macOS native KMS library from one of its two install locations and nowhere else. The
 * library receives every plaintext DEK on unwrap and chooses every "random" DEK on
 * generate-and-wrap, so loading an impostor would hand over every key.
 * <ol>
 * <li><b>Location.</b> The system install, {@link #SYSTEM_DIRECTORY}, is used whenever it exists;
 * the per-user install, {@code ~/.hkdfguard/v1}, only when there is no system install. "~" is the
 * effective user's home from the account database (getpwuid_r), never the user.home property,
 * which {@code -Duser.home} on the command line could point anywhere. Anything
 * running as the user can write to the user's home, so a per-user file must never be able to
 * override a root-owned system one. If the system install exists but fails a check, loading fails -
 * it never falls back to the user install. Nor does it fall back when the system install merely
 * can't be examined (lstat fails with anything but ENOENT or ENOTDIR): only "nothing is there"
 * counts as "not installed".</li>
 * <li><b>Path integrity.</b> No component of the path, from the file up to /, may be a symbolic link,
 * or writable by anyone other than its owner - except that the system directories above an install
 * (/, /Library, /Library/Application Support, /Users) may also be writable by the wheel or admin
 * group when root owns them. Every component of a system install must be owned by root; of a user
 * install, by root or the current user.</li>
 * <li><b>Code signature.</b> The file's signature must be valid and satisfy {@link #CODE_REQUIREMENT}
 * - signed through Apple's CA by the HkdfGuard team.</li>
 * <li><b>Version.</b> The library's own version - LC_ID_DYLIB's current version, in the Mach-O header
 * the signature covers - must be at least {@link #MINIMUM_LIBRARY_VERSION}, so an older release,
 * though genuinely signed, can't be put in place of a current one.</li>
 * <li><b>What dyld loaded.</b> dlopen of an absolute path first looks for the path's leaf name in
 * every DYLD_LIBRARY_PATH directory. So the loader refuses before dlopen if a DYLD_LIBRARY_PATH
 * directory holds a {@link #FILE_NAME}, and after dlopen asks dyld (dladdr) which file it mapped;
 * anything but the verified path is unloaded and refused.</li>
 * </ol>
 * Any failed check throws; there is deliberately no other fallback and no override.
 */
final class MacOsNativeLibraryLoader {
    static final String FILE_NAME = "libhkdfguard.dylib";

    /** The system-wide install, used whenever it exists. */
    static final String SYSTEM_DIRECTORY = "/Library/Application Support/HkdfGuard/v1";

    /** The per-user install, relative to the user's home directory. */
    static final String USER_DIRECTORY_UNDER_HOME = ".hkdfguard/v1";

    /** The Apple team ID the library must be signed by. */
    static final String TEAM_ID = "MFW3T8R8J3";

    /**
     * The code requirement the library's signature must satisfy, matching the release build's own
     * designated requirement: this library's identifier, signed with a Developer ID Application
     * certificate issued to the HkdfGuard team.
     */
    static final String CODE_REQUIREMENT =
            "identifier \"libhkdfguard\" and anchor apple generic"
                    + " and certificate 1[field.1.2.840.113635.100.6.2.6] exists"    // Developer ID CA
                    + " and certificate leaf[field.1.2.840.113635.100.6.1.13] exists" // Developer ID Application leaf
                    + " and certificate leaf[subject.OU] = \"" + TEAM_ID + "\"";

    /**
     * The oldest library release this package loads, as Mach-O packs a version: major &lt;&lt; 16 |
     * minor &lt;&lt; 8 | patch (0.9.0). Raise it when a release fixes a security issue in an older one.
     */
    static final int MINIMUM_LIBRARY_VERSION = 0x0000_0900;

    /** How much of the file is read to find its version: the header and load commands. */
    static final int VERSION_READ_LIMIT = 64 * 1024;

    /** The library's own minimum macOS major version. */
    static final int MINIMUM_MAC_OS_MAJOR_VERSION = 13;

    /** An export every genuine build has; its address tells dladdr which file was loaded. */
    static final String PROBE_EXPORT = "hkdfguard_wrap_dek";

    // gid 0 (wheel) and 80 (admin): on macOS, root-owned system directories such as
    // /Library/Application Support may be writable by these groups. Both are administrators.
    private static final Set<Long> ADMINISTRATIVE_GROUPS = Set.of(0L, 80L);

    // The only directories that exception applies to.
    private static final Set<String> SHARED_SYSTEM_DIRECTORIES = Set.of("/", "/Library", "/Library/Application Support", "/Users");

    private static final int ENOENT = 2;
    private static final int ENOTDIR = 20;

    private static MemorySegment handle;

    private MacOsNativeLibraryLoader() {
    }

    /** The system install's full path. */
    static String systemPath() {
        return SYSTEM_DIRECTORY + "/" + FILE_NAME;
    }

    /** The per-user install's full path under {@code homeDirectory}. */
    static String userPath(String homeDirectory) {
        return stripTrailingSlashes(homeDirectory) + "/" + USER_DIRECTORY_UNDER_HOME + "/" + FILE_NAME;
    }

    /**
     * Verifies and loads the installed library, once per process; later calls return the same
     * handle. A failure isn't cached, so a fixed installation is picked up on the next call.
     *
     * @throws NativeLibraryNotFoundException the library is installed at neither location
     * @throws SecurityException              the installed file or its location failed verification
     */
    static synchronized MemorySegment load() {
        if (handle != null)
            return handle;

        requireSupportedPlatform(CpuArchitecture.current(), System.getProperty("os.version", ""));

        var choice = choosePath(MacOsNative::probe, MacOsNative.accountHomeDirectory());
        List<Long> trustedOwners = choice.isSystem() ? List.of(0L) : List.of(0L, MacOsNative.effectiveUserId());
        verifyLocation(choice.path(), MacOsNative::status, trustedOwners);
        verifySignature(choice.path(), MacOsNative::checkCodeSignature);
        verifyVersion(choice.path(), readHead(choice.path()));
        refuseShadowing(System::getenv, candidate -> Files.exists(Path.of(candidate)));

        // dyld may still map a different file than the path asks for, so the loaded image is
        // checked and, if it isn't the verified file, unloaded.
        var error = new StringBuilder();
        var loaded = MacOsNative.open(choice.path(), error);
        if (loaded == null)
            throw new NativeLibraryNotFoundException("dlopen('" + choice.path() + "') failed: " + error);

        try {
            var probe = MacOsNative.symbol(loaded, PROBE_EXPORT);
            verifyLoadedImage(choice.path(), probe == null ? null : MacOsNative.imagePath(probe));
        } catch (RuntimeException e) {
            MacOsNative.close(loaded);
            throw e;
        }

        handle = loaded;
        return handle;
    }

    /**
     * The address of a named export of a library {@link #load()} returned.
     *
     * @throws IllegalStateException it has no such export
     */
    static MemorySegment export(MemorySegment library, String name) {
        var address = MacOsNative.symbol(library, name);
        if (address == null)
            throw new IllegalStateException("The HkdfGuard native KMS library has no '" + name + "' export.");
        return address;
    }

    /**
     * Requires what the library itself requires: an arm64 process (the library is built for Apple
     * silicon only, and needs its Secure Enclave) on macOS {@link #MINIMUM_MAC_OS_MAJOR_VERSION} or
     * later. Checked first, so an unsupported Mac gets this explanation rather than dyld's.
     *
     * @param processArchitecture the process's architecture - X64 under Rosetta, even on Apple silicon
     * @param osVersion           the macOS version, as the os.version property reports it
     * @throws UnsupportedOperationException either requirement is not met
     */
    static void requireSupportedPlatform(CpuArchitecture processArchitecture, String osVersion) {
        if (processArchitecture != CpuArchitecture.ARM64)
            throw new UnsupportedOperationException(
                    "The HkdfGuard native KMS library requires Apple silicon: an arm64 process on an arm64 Mac. This process is " + processArchitecture
                            + (processArchitecture == CpuArchitecture.X64
                            ? " - an Intel Mac, or an x64 Java runtime running under Rosetta; on Apple silicon, use the arm64 Java runtime."
                            : "."));

        if (majorVersion(osVersion) < MINIMUM_MAC_OS_MAJOR_VERSION)
            throw new UnsupportedOperationException(
                    "The HkdfGuard native KMS library requires macOS " + MINIMUM_MAC_OS_MAJOR_VERSION + " or later; this is macOS " + osVersion + ".");
    }

    private static int majorVersion(String version) {
        var end = 0;
        while (end < version.length() && Character.isDigit(version.charAt(end)))
            end++;
        return end == 0 ? 0 : Integer.parseInt(version.substring(0, end));
    }

    /** Which install was chosen. */
    record PathChoice(String path, boolean isSystem) {
    }

    /**
     * The system install if it exists, otherwise the user install if that exists. "Exists" is
     * decided by lstat, so that "can't look" is never mistaken for "not there".
     *
     * @param probe lstat's result for a path: 0 if it exists, else the errno
     * @throws NativeLibraryNotFoundException neither exists
     * @throws SecurityException              an install location could not be examined
     */
    static PathChoice choosePath(ToIntFunction<String> probe, String homeDirectory) {
        if (isPresent(systemPath(), probe, "system-wide"))
            return new PathChoice(systemPath(), true);

        // No account-database home, or a relative one (which would resolve against the working
        // directory): only the system install is considered.
        if (homeDirectory == null || !homeDirectory.startsWith("/"))
            throw new NativeLibraryNotFoundException("The HkdfGuard native KMS library is not installed. Install it at '" + systemPath()
                    + "' (system-wide); it is never loaded from anywhere else.");

        var user = userPath(homeDirectory);
        if (isPresent(user, probe, "per-user"))
            return new PathChoice(user, false);

        throw new NativeLibraryNotFoundException("The HkdfGuard native KMS library is not installed. Install it at '" + systemPath()
                + "' (system-wide) or '" + user + "' (this user); it is never loaded from anywhere else.");
    }

    /**
     * Refuses a library older than {@link #MINIMUM_LIBRARY_VERSION}, or one whose version can't be
     * read. {@code head} is the start of the verified file (see {@link #readHead}).
     *
     * @throws SecurityException the version is missing, unreadable or too old
     */
    static void verifyVersion(String path, byte[] head) {
        var version = readLibraryVersion(head);
        if (version == null)
            throw new SecurityException("'" + path + "' is not an arm64 Mach-O library whose version can be read; refusing to load it.");
        if (Integer.compareUnsigned(version, MINIMUM_LIBRARY_VERSION) < 0)
            throw new SecurityException("'" + path + "' is HkdfGuard native library version " + formatVersion(version)
                    + ", older than the minimum this package accepts (" + formatVersion(MINIMUM_LIBRARY_VERSION) + "); install a current release.");
    }

    /** Major.minor.patch of a Mach-O packed version. */
    static String formatVersion(int packed) {
        return (packed >>> 16) + "." + ((packed >>> 8) & 0xFF) + "." + (packed & 0xFF);
    }

    /** The first {@link #VERSION_READ_LIMIT} bytes of the file (fewer if it's shorter). */
    private static byte[] readHead(String path) {
        try (var stream = Files.newInputStream(Path.of(path))) {
            return stream.readNBytes(VERSION_READ_LIMIT);
        } catch (java.io.IOException e) {
            throw new SecurityException("Could not read '" + path + "' to check its version; refusing to load it.", e);
        }
    }

    private static final int MACH_MAGIC_64 = 0xFEEDFACF;  // MH_MAGIC_64, little-endian on arm64
    private static final int FAT_MAGIC = 0xCAFEBABE;      // FAT_MAGIC, big-endian
    private static final int FAT_MAGIC_64 = 0xCAFEBABF;   // FAT_MAGIC_64, big-endian
    private static final int CPU_TYPE_ARM64 = 0x0100000C; // CPU_TYPE_ARM64
    private static final int LC_ID_DYLIB = 0xD;
    private static final int MACH_HEADER_64_SIZE = 32;
    private static final int DYLIB_COMMAND_SIZE = 24;     // current_version is at offset 16

    /**
     * The current version in an arm64 Mach-O library's LC_ID_DYLIB, from {@code data}, the start of
     * the file; null if it is malformed, not arm64, has no LC_ID_DYLIB, or its header and load
     * commands don't fit in {@code data}. A universal (fat) file is read through its arm64 slice.
     * Every length is checked before it is used.
     */
    static Integer readLibraryVersion(byte[] data) {
        if (data.length < 8)
            return null;
        var big = java.nio.ByteBuffer.wrap(data).order(java.nio.ByteOrder.BIG_ENDIAN);
        var magic = big.getInt(0);
        if (magic == FAT_MAGIC || magic == FAT_MAGIC_64) {
            var entrySize = magic == FAT_MAGIC ? 20 : 32;
            var count = Integer.toUnsignedLong(big.getInt(4));
            if (count > (data.length - 8L) / entrySize)
                return null;
            for (var i = 0; i < count; i++) {
                var entry = 8 + i * entrySize;
                if (big.getInt(entry) != CPU_TYPE_ARM64)
                    continue;
                var offset = magic == FAT_MAGIC ? Integer.toUnsignedLong(big.getInt(entry + 8)) : big.getLong(entry + 8);
                if (offset < 0 || offset >= data.length)
                    return null;
                return readThinLibraryVersion(java.util.Arrays.copyOfRange(data, (int) offset, data.length));
            }
            return null;
        }
        return readThinLibraryVersion(data);
    }

    private static Integer readThinLibraryVersion(byte[] data) {
        if (data.length < MACH_HEADER_64_SIZE)
            return null;
        var le = java.nio.ByteBuffer.wrap(data).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        if (le.getInt(0) != MACH_MAGIC_64 || le.getInt(4) != CPU_TYPE_ARM64)
            return null;

        var commandCount = Integer.toUnsignedLong(le.getInt(16));
        var commandsSize = Integer.toUnsignedLong(le.getInt(20));
        if (commandsSize > data.length - MACH_HEADER_64_SIZE || commandCount > commandsSize / 8)
            return null;

        long at = MACH_HEADER_64_SIZE;
        var end = MACH_HEADER_64_SIZE + commandsSize;
        for (long i = 0; i < commandCount; i++) {
            if (end - at < 8)
                return null;
            var command = le.getInt((int) at);
            var size = Integer.toUnsignedLong(le.getInt((int) at + 4));
            if (size < 8 || size % 8 != 0 || size > end - at)
                return null;
            if (command == LC_ID_DYLIB)
                return size < DYLIB_COMMAND_SIZE ? null : le.getInt((int) at + 16);
            at += size;
        }
        return null;
    }

    // ENOENT and ENOTDIR: nothing is installed there. Anything else (EACCES, ELOOP, EIO, ...) means
    // something may well be there that this process isn't allowed to see; a system install hidden
    // that way must not let the per-user one take its place.
    private static boolean isPresent(String path, ToIntFunction<String> probe, String kind) {
        var errno = probe.applyAsInt(path);
        if (errno == 0)
            return true;
        if (errno == ENOENT || errno == ENOTDIR)
            return false;

        throw new SecurityException("Could not tell whether the " + kind + " HkdfGuard native library '" + path + "' exists (lstat failed with errno "
                + errno + "); refusing to guess or to fall back to another location.");
    }

    /**
     * The dyld variables whose presence alone refuses the load: each makes dyld inject code into
     * this process, or load another file in place of a library it names - including the frameworks
     * the HkdfGuard native library calls with every DEK. None is set on a production host.
     */
    static final java.util.List<String> REFUSED_DYLD_VARIABLES = java.util.List.of(
            "DYLD_INSERT_LIBRARIES", "DYLD_FRAMEWORK_PATH", "DYLD_VERSIONED_LIBRARY_PATH", "DYLD_VERSIONED_FRAMEWORK_PATH", "DYLD_IMAGE_SUFFIX");

    /**
     * Refuses, before anything is loaded, if one of {@link #REFUSED_DYLD_VARIABLES} is set, or a
     * DYLD_LIBRARY_PATH directory contains a file named {@link #FILE_NAME}: dyld would load that in
     * place of the verified path.
     * <p>
     * A guard against a misconfigured environment, not against whoever controls it: dyld acts on
     * these variables when the process starts, so code they injected has already run - and can hide
     * - by the time this looks. Running the host with the Hardened Runtime, which makes dyld ignore
     * them, is what keeps that code out.
     *
     * @param getEnvironmentVariable reads an environment variable; null if unset
     * @param exists                 whether a path exists
     * @throws SecurityException a refused variable is set, or a shadowing library was found
     */
    static void refuseShadowing(Function<String, String> getEnvironmentVariable, Predicate<String> exists) {
        for (var name : REFUSED_DYLD_VARIABLES) {
            var value = getEnvironmentVariable.apply(name);
            if (value != null && !value.isEmpty())
                throw new SecurityException(name + " is set, so dyld may inject code into this process or substitute a library the HkdfGuard native library uses; refusing to load it. Unset " + name + ".");
        }

        var searchPath = getEnvironmentVariable.apply("DYLD_LIBRARY_PATH");
        if (searchPath == null || searchPath.isEmpty())
            return;

        for (var directory : searchPath.split(":")) {
            if (directory.isEmpty())
                continue;

            var candidate = stripTrailingSlashes(directory) + "/" + FILE_NAME;
            if (exists.test(candidate))
                throw new SecurityException("'" + candidate + "' is on DYLD_LIBRARY_PATH and would be loaded in place of the verified HkdfGuard native library; refusing to load. Remove it from DYLD_LIBRARY_PATH.");
        }
    }

    /**
     * Requires that the file dyld reports having loaded is the one that was verified.
     *
     * @param loadedPath the path dladdr reports for the loaded library's export, or null if it has
     *                   no such export or dyld can't say
     * @throws SecurityException they differ
     */
    static void verifyLoadedImage(String expectedPath, String loadedPath) {
        if (loadedPath == null)
            throw new SecurityException("The library loaded for '" + expectedPath + "' has no '" + PROBE_EXPORT
                    + "' export, or dyld cannot say where it came from; it is not the HkdfGuard native library and has been unloaded.");

        if (!loadedPath.equals(expectedPath))
            throw new SecurityException("dyld loaded '" + loadedPath + "' in place of the verified '" + expectedPath
                    + "' (DYLD_LIBRARY_PATH, most likely); it has been unloaded and the HkdfGuard native library was not loaded.");
    }

    /**
     * Checks the file and every parent directory up to /: not a symbolic link, owned by one of
     * {@code trustedOwners}, and not writable by anyone else.
     *
     * @throws SecurityException a path component failed a check
     */
    static void verifyLocation(String path, Function<String, UnixFileStatus> getStatus, Collection<Long> trustedOwners) {
        var file = getStatus.apply(path);
        if (file.type() != UnixFileType.REGULAR_FILE)
            throw new SecurityException("'" + path + "' is not a regular file (it is a " + describe(file.type()) + ").");
        verifyComponent(path, file, trustedOwners);

        for (var directory = parentOf(path); directory != null; directory = parentOf(directory)) {
            var status = getStatus.apply(directory);
            if (status.type() != UnixFileType.DIRECTORY)
                throw new SecurityException("'" + directory + "' is not a directory (it is a " + describe(status.type())
                        + "); the library is only loaded through a real path.");
            verifyComponent(directory, status, trustedOwners);
        }
    }

    static void verifyComponent(String path, UnixFileStatus status, Collection<Long> trustedOwners) {
        // Root owns the system directories above every install (/, /Library, /Users).
        if (status.ownerId() != 0 && !trustedOwners.contains(status.ownerId()))
            throw new SecurityException("'" + path + "' is owned by uid " + status.ownerId() + "; the HkdfGuard native library is only loaded from a location owned by "
                    + (trustedOwners.size() == 1 ? "root" : "root or the current user") + ".");

        if (status.permissions().contains(PosixFilePermission.OTHERS_WRITE))
            throw new SecurityException("'" + path + "' is writable by every user; the HkdfGuard native library is only loaded from a location only its owner can modify.");

        if (status.permissions().contains(PosixFilePermission.GROUP_WRITE)
                && !(status.ownerId() == 0 && ADMINISTRATIVE_GROUPS.contains(status.groupId()) && SHARED_SYSTEM_DIRECTORIES.contains(path)))
            throw new SecurityException("'" + path + "' is writable by group " + status.groupId()
                    + "; the HkdfGuard native library is only loaded from a location only its owner can modify (administrators may also write only to the system directories above an install: "
                    + String.join(", ", new TreeSet<>(SHARED_SYSTEM_DIRECTORIES)) + ").");
    }

    /**
     * Requires a valid code signature that satisfies {@link #CODE_REQUIREMENT}.
     *
     * @param checkSignature returns 0 (errSecSuccess) when the signature is valid and satisfies the
     *                       requirement, else the OSStatus
     * @throws SecurityException the signature is missing, invalid, or from another team
     */
    static void verifySignature(String path, ToIntBiFunction<String, String> checkSignature) {
        var status = checkSignature.applyAsInt(path, CODE_REQUIREMENT);
        if (status != 0)
            throw new SecurityException("'" + path + "' is not validly signed by the HkdfGuard team (" + TEAM_ID + "); code signature check failed with OSStatus " + status + ".");
    }

    // macOS paths are always '/'-separated, whatever platform runs the tests. Null above /.
    static String parentOf(String path) {
        if (path.equals("/"))
            return null;

        var slash = stripTrailingSlashes(path).lastIndexOf('/');
        return slash <= 0 ? "/" : path.substring(0, slash);
    }

    private static String stripTrailingSlashes(String path) {
        var end = path.length();
        while (end > 0 && path.charAt(end - 1) == '/')
            end--;
        return path.substring(0, end);
    }

    private static String describe(UnixFileType type) {
        return switch (type) {
            case SYMBOLIC_LINK -> "symbolic link";
            case DIRECTORY -> "directory";
            case REGULAR_FILE -> "regular file";
            case OTHER -> "special file";
        };
    }
}
