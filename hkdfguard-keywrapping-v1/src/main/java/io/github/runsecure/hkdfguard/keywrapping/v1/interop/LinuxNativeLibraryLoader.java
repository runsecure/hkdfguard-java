package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import io.github.runsecure.hkdfguard.keywrapping.v1.NativeLibraryNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.ToIntFunction;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;

/**
 * Loads the Linux native KMS library from its package's install location and nowhere else. The
 * library receives every plaintext DEK on unwrap and chooses every "random" DEK on
 * generate-and-wrap, and the tpm2-tss library it loads receives every ECDH shared secret, so
 * loading an impostor of either would hand over every key. Loading by name would search
 * LD_LIBRARY_PATH and the linker's cache; this loader replaces that.
 * <ol>
 * <li><b>Location.</b> The file the libhkdfguard1 package installs: the Debian multiarch directory
 * (/usr/lib/x86_64-linux-gnu or /usr/lib/aarch64-linux-gnu) if it is there, otherwise /usr/lib64
 * (the RPM packages). Only "nothing is there" moves on to the next location; a path that can't be
 * examined is refused.</li>
 * <li><b>Path integrity.</b> Every directory walked through, every symbolic link followed, and the
 * file itself must be owned by root, and no directory or file may be writable by its group or by
 * others. Symbolic links are followed component by component, each one checked where it lies, so a
 * link can only lead somewhere root chose (/lib to usr/lib, say).</li>
 * <li><b>Content.</b> The file's SHA-256 must be one of {@link #KNOWN_RELEASES}. Linux has no
 * platform code signature to check, so this pin is what tells a genuine release from any other ELF
 * file root may have put at that path.</li>
 * <li><b>Environment.</b> An absolute path is never searched for, but the library's dependencies
 * are found by name: through LD_LIBRARY_PATH, and after LD_PRELOAD and LD_AUDIT objects that can
 * interpose on any symbol. So every directory on LD_LIBRARY_PATH and every path-named LD_PRELOAD or
 * LD_AUDIT object must pass the same path checks, and none may be relative, empty (the working
 * directory) or use $ORIGIN-style substitutions. Both the environment the process started with
 * (/proc/self/environ, what the dynamic linker read) and the current one are checked.</li>
 * <li><b>What was loaded.</b> After dlopen, dladdr must place the library's export in the verified
 * file, and every object in its dependency closure (read from each file's DT_NEEDED entries) must
 * be bound to a file that passes the path checks. This catches a dependency the process had already
 * loaded from somewhere else under the same name. On failure the library is unloaded - though, as on
 * macOS, any initializer an impostor had has already run; the environment check exists so that it
 * never gets that far in practice.</li>
 * </ol>
 * Any failed check throws; there is deliberately no fallback and no override. The policy is the same
 * as the .NET port's LinuxNativeLibraryLoader, check for check.
 * <p>
 * Two things are out of reach here. The tpm2-tss TCTI module is loaded later, at the first TPM
 * call, by name; the environment check is what covers it. And the JVM's own injection points
 * (-agentpath, -javaagent, JAVA_TOOL_OPTIONS) are not dynamic-linker settings; protect the
 * service's command line and environment for those, as on every platform.
 */
@SuppressWarnings("restricted") // Loads the library through the FFM API; the module requires --enable-native-access.
final class LinuxNativeLibraryLoader {
    /** The library's SONAME, which the package installs as a regular file. */
    static final String FILE_NAME = "libhkdfguard.so.1";

    /** The RPM packages' library directory, used when there is no Debian multiarch one. */
    static final String LIB64_DIRECTORY = "/usr/lib64";

    /** An export every genuine build has; its address tells dladdr which file was loaded. */
    static final String PROBE_EXPORT = "hkdfguard_wrap_dek";

    /**
     * The SHA-256 of every native release this library accepts, with what it is. Each distribution
     * and architecture gets its own build, so each needs its own entry; a release whose hash is not
     * here is refused until this library is updated to list it.
     * <p>
     * Keep this list in sync with KnownReleases in the .NET port's LinuxNativeLibraryLoader
     * (hkdfguard-dotnet, src/HkdfGuard.KeyWrapping.V1/Interop/LinuxNativeLibraryLoader.cs): both
     * ports must accept exactly the same native releases.
     */
    static final Map<String, String> KNOWN_RELEASES = Map.of(
            "a3a9312fd2d603a62e6a5b1ed46ba5e4a51adcba321aa5a1014a762ff07ca064", "libhkdfguard1 0.1.0-1~ubuntu24.04.1 (amd64)");

    // The dynamic-linker variables that decide where, or what, it loads.
    static final String LIBRARY_PATH_VARIABLE = "LD_LIBRARY_PATH";
    static final String PRELOAD_VARIABLE = "LD_PRELOAD";
    static final String AUDIT_VARIABLE = "LD_AUDIT";

    /** The kernel's own limit on symbolic links followed in one lookup. */
    static final int MAX_SYMBOLIC_LINKS = 40;

    private static final int ENOENT = 2;
    private static final int ENOTDIR = 20;

    private static SymbolLookup library;

    private LinuxNativeLibraryLoader() {
    }

    /**
     * Verifies and loads the installed library, once per process; later calls return the same
     * lookup. A failure isn't cached, so a fixed installation is picked up on the next call.
     *
     * @throws UnsupportedOperationException  the process is neither x64 nor arm64
     * @throws NativeLibraryNotFoundException the library is not installed
     * @throws SecurityException              the installed file, its location, its dependencies or the environment failed verification
     */
    static synchronized SymbolLookup load() {
        if (library != null)
            return library;

        var candidates = candidatePaths(CpuArchitecture.current());
        var path = resolveTrusted(choosePath(candidates, LinuxNative::probe), UnixFileType.REGULAR_FILE, LinuxNative::statusOrNull, LinuxNative::readLink);
        verifyContent(path, LinuxNativeLibraryLoader::hashFile, KNOWN_RELEASES);

        var environment = readEnvironment(System::getenv, LinuxNative.readInitialEnvironment());
        verifyEnvironment(environment, (p, type) -> resolveTrusted(p, type, LinuxNative::statusOrNull, LinuxNative::readLink, true));

        // Loaded by the verified absolute, link-free path only - never by name. Closing the arena
        // unloads it again.
        var arena = Arena.ofShared();
        SymbolLookup loaded;
        try {
            loaded = SymbolLookup.libraryLookup(Path.of(path), arena);
        } catch (RuntimeException e) {
            arena.close();
            throw new NativeLibraryNotFoundException("The HkdfGuard native KMS library '" + path + "' passed verification but could not be loaded: " + e.getMessage(), e);
        }

        try {
            UnaryOperator<String> trusted = p -> resolveTrusted(p, UnixFileType.REGULAR_FILE, LinuxNative::statusOrNull, LinuxNative::readLink);

            var image = loaded.find(PROBE_EXPORT).map(LinuxNative::imagePath).orElse(null);
            verifyLoadedImage(path, image == null ? null : trusted.apply(image));
            verifyDependencies(path, ElfDependencies::readNeeded, LinuxNative::loadedPath, trusted);
        } catch (RuntimeException e) {
            arena.close();
            throw e;
        }

        library = loaded;
        return library;
    }

    /**
     * The address of a named export of a library {@link #load()} returned.
     *
     * @throws IllegalStateException it has no such export
     */
    static MemorySegment export(SymbolLookup library, String name) {
        return library.find(name)
                .orElseThrow(() -> new IllegalStateException("The HkdfGuard native KMS library has no '" + name + "' export."));
    }

    /**
     * Where the package may have installed the library for a process of {@code processArchitecture},
     * in the order they are tried.
     *
     * @throws UnsupportedOperationException no package is built for that architecture
     */
    static List<String> candidatePaths(CpuArchitecture processArchitecture) {
        var triplet = switch (processArchitecture) {
            case X64 -> "x86_64-linux-gnu";
            case ARM64 -> "aarch64-linux-gnu";
            default -> throw new UnsupportedOperationException(
                    "The HkdfGuard native KMS library is built for x64 and arm64 Linux only; this process is " + processArchitecture + ".");
        };

        return List.of("/usr/lib/" + triplet + "/" + FILE_NAME, LIB64_DIRECTORY + "/" + FILE_NAME);
    }

    /**
     * The first candidate that exists. "Exists" is decided by statx, so "can't look" is never
     * mistaken for "not there".
     *
     * @param probe statx's result for a path: 0 if it exists, else the errno
     * @throws NativeLibraryNotFoundException none exists
     * @throws SecurityException              a candidate could not be examined
     */
    static String choosePath(List<String> candidates, ToIntFunction<String> probe) {
        for (var candidate : candidates) {
            var errno = probe.applyAsInt(candidate);
            if (errno == 0)
                return candidate;
            if (errno != ENOENT && errno != ENOTDIR)
                throw new SecurityException("Could not tell whether the HkdfGuard native library '" + candidate + "' exists (statx failed with errno "
                        + errno + "); refusing to guess or to fall back to another location.");
        }

        throw new NativeLibraryNotFoundException(
                "The HkdfGuard native KMS library is not installed. Install the libhkdfguard1 package (hkdfguard-libs on RPM distributions); it is loaded only from "
                        + candidates.stream().map(c -> "'" + c + "'").collect(Collectors.joining(" or ")) + ".");
    }

    /**
     * {@link #resolveTrusted(String, UnixFileType, Function, Function, boolean)} with a missing path
     * refused.
     */
    static String resolveTrusted(String path, UnixFileType expectedType, Function<String, UnixFileStatus> getStatus, Function<String, String> readLink) {
        return resolveTrusted(path, expectedType, getStatus, readLink, false);
    }

    /**
     * Resolves {@code path} the way the kernel would, checking everything it passes through: every
     * directory and the final object must be owned by root and writable by neither group nor
     * others, and every symbolic link must be owned by root (its target is then resolved and checked
     * in turn). Returns the resolved path, which contains no symbolic links.
     *
     * @param getStatus    lstat-style status of a path, or null if nothing is there
     * @param readLink     a symbolic link's stored target, or null if it can't be read as one
     * @param allowMissing when true, a path that runs into a missing component returns null instead
     *                     of throwing: everything up to it was checked, so only root could create
     *                     what is missing
     * @throws SecurityException a check failed, or the final object is not of {@code expectedType}
     */
    static String resolveTrusted(String path, UnixFileType expectedType, Function<String, UnixFileStatus> getStatus, Function<String, String> readLink,
            boolean allowMissing) {
        if (!path.startsWith("/"))
            throw new SecurityException("'" + path + "' is not an absolute path; the HkdfGuard native library and its dependencies are only trusted at absolute paths.");

        var root = getStatus.apply("/");
        if (root == null)
            throw new SecurityException("'/' could not be examined.");
        requireRootControlled("/", root);

        Deque<String> pending = new ArrayDeque<>();
        pushComponents(pending, path);
        var resolved = "/";
        var resolvedType = UnixFileType.DIRECTORY;
        var linksFollowed = 0;

        while (!pending.isEmpty()) {
            var name = pending.pop();
            if (name.isEmpty() || name.equals("."))
                continue;

            if (resolvedType != UnixFileType.DIRECTORY)
                throw new SecurityException("'" + path + "' runs through '" + resolved + "', which is not a directory.");

            if (name.equals("..")) {
                // resolved never contains a symbolic link, so its parent is its lexical parent.
                resolved = parentOf(resolved);
                continue;
            }

            var candidate = resolved.equals("/") ? "/" + name : resolved + "/" + name;
            var status = getStatus.apply(candidate);
            if (status == null) {
                if (allowMissing)
                    return null;
                throw new SecurityException("'" + candidate + "' does not exist (resolving '" + path + "').");
            }

            if (status.type() == UnixFileType.SYMBOLIC_LINK) {
                if (status.ownerId() != 0)
                    throw new SecurityException("'" + candidate + "' is a symbolic link owned by uid " + status.ownerId()
                            + "; only links owned by root are followed (resolving '" + path + "').");
                if (++linksFollowed > MAX_SYMBOLIC_LINKS)
                    throw new SecurityException("'" + path + "' follows more than " + MAX_SYMBOLIC_LINKS + " symbolic links.");

                var target = readLink.apply(candidate);
                if (target == null)
                    throw new SecurityException("'" + candidate + "' could not be read as a symbolic link.");
                if (target.startsWith("/"))
                    resolved = "/";
                pushComponents(pending, target);
                continue;
            }

            requireRootControlled(candidate, status);
            resolved = candidate;
            resolvedType = status.type();
        }

        if (resolvedType != expectedType)
            throw new SecurityException("'" + path + "' resolves to '" + resolved + "', which is a " + describe(resolvedType) + ", not a " + describe(expectedType) + ".");

        return resolved;
    }

    private static void requireRootControlled(String path, UnixFileStatus status) {
        if (status.ownerId() != 0)
            throw new SecurityException("'" + path + "' is owned by uid " + status.ownerId()
                    + "; the HkdfGuard native library and its dependencies are only trusted in locations owned by root.");

        if (status.permissions().contains(PosixFilePermission.GROUP_WRITE) || status.permissions().contains(PosixFilePermission.OTHERS_WRITE))
            throw new SecurityException("'" + path
                    + "' is writable by its group or by every user; the HkdfGuard native library and its dependencies are only trusted in locations only root can modify.");
    }

    private static void pushComponents(Deque<String> pending, String path) {
        var components = path.split("/", -1);
        for (var i = components.length - 1; i >= 0; i--)
            pending.push(components[i]);
    }

    static String parentOf(String path) {
        var slash = path.lastIndexOf('/');
        return slash <= 0 ? "/" : path.substring(0, slash);
    }

    /**
     * Requires the file's SHA-256 to be a known release.
     *
     * @param sha256Hex the file's SHA-256, as lowercase hex
     * @throws SecurityException it isn't
     */
    static void verifyContent(String path, Function<String, String> sha256Hex, Map<String, String> knownReleases) {
        var hash = sha256Hex.apply(path);
        if (!knownReleases.containsKey(hash))
            throw new SecurityException("'" + path + "' has SHA-256 " + hash
                    + ", which is not a HkdfGuard native release this version of hkdfguard-keywrapping-v1 recognizes; refusing to load it. If it is a newer genuine release, update hkdfguard-keywrapping-v1.");
    }

    private static String hashFile(String path) {
        try (InputStream stream = Files.newInputStream(Path.of(path))) {
            var digest = MessageDigest.getInstance("SHA-256");
            var buffer = new byte[64 * 1024];
            for (int read; (read = stream.read(buffer)) > 0; )
                digest.update(buffer, 0, read);
            return HexFormat.of().formatHex(digest.digest());
        } catch (IOException e) {
            throw new SecurityException("'" + path + "' could not be read to verify it: " + e.getMessage(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available.", e);
        }
    }

    /**
     * Every value each dynamic-linker variable has had: in the environment the process started with
     * ({@code initialEnvironment}, /proc/self/environ's NUL-separated block, if it could be read)
     * and in the current one.
     *
     * @param current reads a current environment variable; null if unset
     * @return each of the three variables, mapped to its values (empty if it never had one)
     */
    static Map<String, List<String>> readEnvironment(Function<String, String> current, byte[] initialEnvironment) {
        var names = List.of(LIBRARY_PATH_VARIABLE, PRELOAD_VARIABLE, AUDIT_VARIABLE);
        var values = new LinkedHashMap<String, List<String>>();
        for (var name : names)
            values.put(name, new ArrayList<>());

        if (initialEnvironment != null) {
            for (var entry : new String(initialEnvironment, StandardCharsets.UTF_8).split("\0", -1)) {
                var equals = entry.indexOf('=');
                if (equals > 0) {
                    var list = values.get(entry.substring(0, equals));
                    if (list != null)
                        list.add(entry.substring(equals + 1));
                }
            }
        }

        for (var name : names) {
            var value = current.apply(name);
            if (value != null && !values.get(name).contains(value))
                values.get(name).add(value);
        }

        var result = new LinkedHashMap<String, List<String>>();
        values.forEach((name, list) -> result.put(name, List.copyOf(list)));
        return Collections.unmodifiableMap(result);
    }

    /**
     * Requires every location the dynamic-linker variables could make it load from to pass the
     * path checks.
     *
     * @param environment    every value of each variable (see {@link #readEnvironment})
     * @param resolveTrusted {@link #resolveTrusted} with missing paths allowed: throws if the path is
     *                       untrusted, returns null if nothing is there
     * @throws SecurityException a value names a location that isn't trusted
     */
    static void verifyEnvironment(Map<String, List<String>> environment, BiFunction<String, UnixFileType, String> resolveTrusted) {
        // An empty LD_LIBRARY_PATH is ignored by the dynamic linker; an empty entry within one is
        // the working directory.
        for (var value : environment.getOrDefault(LIBRARY_PATH_VARIABLE, List.of())) {
            if (value.isEmpty())
                continue;

            for (var entry : value.split("[:;]", -1)) {
                if (entry.isEmpty())
                    throw untrusted(LIBRARY_PATH_VARIABLE, value, "an empty entry, which means the working directory");
                verifyLocation(LIBRARY_PATH_VARIABLE, value, entry, UnixFileType.DIRECTORY, resolveTrusted);
            }
        }

        // Objects to preload or audit: separated by spaces or colons (LD_PRELOAD), or colons
        // (LD_AUDIT). A bare name is found by the same search as any dependency, which the
        // LD_LIBRARY_PATH check above already covers.
        for (var variable : List.of(PRELOAD_VARIABLE, AUDIT_VARIABLE)) {
            var separators = variable.equals(PRELOAD_VARIABLE) ? "[ :]" : ":";
            for (var value : environment.getOrDefault(variable, List.of())) {
                for (var entry : value.split(separators)) {
                    if (!entry.isEmpty() && (entry.contains("/") || entry.contains("$")))
                        verifyLocation(variable, value, entry, UnixFileType.REGULAR_FILE, resolveTrusted);
                }
            }
        }
    }

    private static void verifyLocation(String variable, String value, String entry, UnixFileType type, BiFunction<String, UnixFileType, String> resolveTrusted) {
        if (entry.contains("$"))
            throw untrusted(variable, value, "'" + entry + "', which uses a dynamic string token ($ORIGIN, $LIB or $PLATFORM) that can't be checked in advance");
        if (!entry.startsWith("/"))
            throw untrusted(variable, value, "'" + entry + "', which is relative to the working directory");

        try {
            resolveTrusted.apply(entry, type);
        } catch (SecurityException | UncheckedIOException e) {
            throw new SecurityException(variable + " ('" + value + "') names '" + entry
                    + "', which the dynamic linker could load the HkdfGuard native library's dependencies from: " + messageOf(e) + " Remove it from " + variable
                    + ", or make it a location only root can modify.", e);
        }
    }

    private static SecurityException untrusted(String variable, String value, String what) {
        return new SecurityException(variable + " ('" + value + "') contains " + what
                + "; the dynamic linker could load the HkdfGuard native library's dependencies from there. Refusing to load it.");
    }

    /**
     * Requires that the file the dynamic linker reports having loaded is the one that was verified.
     *
     * @param expectedPath the verified path that was passed to dlopen
     * @param loadedPath   the resolved path dladdr reports for the library's export, or null if it has
     *                     no such export or the linker can't say
     * @throws SecurityException they differ
     */
    static void verifyLoadedImage(String expectedPath, String loadedPath) {
        if (loadedPath == null)
            throw new SecurityException("The library loaded for '" + expectedPath + "' has no '" + PROBE_EXPORT
                    + "' export, or the dynamic linker cannot say where it came from; it is not the HkdfGuard native library and has been unloaded.");

        if (!loadedPath.equals(expectedPath))
            throw new SecurityException("The dynamic linker bound '" + expectedPath + "' to '" + loadedPath
                    + "', a different file; it has been unloaded and the HkdfGuard native library was not loaded.");
    }

    /**
     * Walks the library's dependency closure - each file's DT_NEEDED names, then theirs - and
     * requires every one to be bound to a trusted file.
     *
     * @param libraryPath    the verified library
     * @param readNeeded     a file's DT_NEEDED names
     * @param loadedPathOf   the path of the already-loaded object a name is bound to, or null if none is
     * @param resolveTrusted resolves a path, throwing unless it passes the path checks
     * @throws SecurityException a dependency is not loaded from a trusted file
     */
    static void verifyDependencies(String libraryPath, Function<String, List<String>> readNeeded, Function<String, String> loadedPathOf,
            UnaryOperator<String> resolveTrusted) {
        var visited = new HashSet<String>();
        visited.add(libraryPath);
        Deque<String> pending = new ArrayDeque<>(List.of(libraryPath));

        while (!pending.isEmpty()) {
            var file = pending.removeFirst();
            for (var name : readNeeded.apply(file)) {
                var loaded = loadedPathOf.apply(name);
                if (loaded == null)
                    throw new SecurityException("'" + file + "' depends on '" + name + "', but no loaded object answers to that name; cannot tell where it came from.");

                String resolved;
                try {
                    resolved = resolveTrusted.apply(loaded);
                } catch (SecurityException | UncheckedIOException e) {
                    throw new SecurityException("The HkdfGuard native library's dependency '" + name + "' (needed by '" + file + "') was loaded from '" + loaded
                            + "', which is not trusted: " + messageOf(e), e);
                }

                if (visited.add(resolved))
                    pending.addLast(resolved);
            }
        }
    }

    // An UncheckedIOException's own message is its cause's toString(); the cause's message reads better.
    private static String messageOf(RuntimeException e) {
        return e instanceof UncheckedIOException && e.getCause() != null ? e.getCause().getMessage() : e.getMessage();
    }

    // Never a symbolic link: resolveTrusted always follows them.
    private static String describe(UnixFileType type) {
        return switch (type) {
            case DIRECTORY -> "directory";
            case REGULAR_FILE -> "regular file";
            default -> "special file";
        };
    }
}
