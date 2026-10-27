package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import io.github.runsecure.hkdfguard.keywrapping.v1.NativeLibraryNotFoundException;
import io.github.runsecure.hkdfguard.platform.unix.UnixFileStatus;
import io.github.runsecure.hkdfguard.platform.unix.UnixFileType;
import io.github.runsecure.hkdfguard.platform.unix.UnixPathResolver;
import io.github.runsecure.hkdfguard.platform.unix.UnixPathResolver.Resolution;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
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
 * <li><b>Environment.</b> An absolute path is never searched for, but the library's dependencies
 * are found by name: through LD_LIBRARY_PATH, and after LD_PRELOAD and LD_AUDIT objects that can
 * interpose on any symbol. So every directory on LD_LIBRARY_PATH and every path-named LD_PRELOAD or
 * LD_AUDIT object must pass the same path checks, and none may be relative, empty (the working
 * directory) or use $ORIGIN-style substitutions. Both the environment the process started with
 * (/proc/self/environ, what the dynamic linker read) and the current one are checked.</li>
 * <li><b>What would be loaded.</b> Before dlopen, the process's own dynamic linker (its PT_INTERP,
 * which must pass the path checks) is asked, in list mode (ld.so --list, the mechanism ldd uses),
 * where it would find every object the library pulls in, under the LD_LIBRARY_PATH and LD_PRELOAD
 * the process started with. List mode resolves exactly as dlopen would - RUNPATH, ld.so.cache and
 * all - but runs none of the libraries' code, so every path it reports must pass the path checks
 * before any of it can run here. A name it can't find refuses the load.</li>
 * <li><b>What was loaded.</b> After dlopen, dladdr must place the library's export in the verified
 * file, and every object in its dependency closure (read from each file's DT_NEEDED entries) must
 * be bound to a file that passes the path checks. This catches what list mode can't see: a
 * dependency name the process had already bound to some other object before the library was
 * loaded. On failure the library is unloaded - though, as on macOS, any initializer an impostor had
 * has already run; the environment check and the list run exist so that it never gets that far in
 * practice.</li>
 * </ol>
 * The file's content is not pinned: a release's authenticity is verified with Sigstore/cosign when
 * the package is installed, so path integrity is what this loader enforces.
 * <p>
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

    // The dynamic-linker variables that decide where, or what, it loads.
    static final String LIBRARY_PATH_VARIABLE = "LD_LIBRARY_PATH";
    static final String PRELOAD_VARIABLE = "LD_PRELOAD";
    static final String AUDIT_VARIABLE = "LD_AUDIT";

    /** Where the kernel shows this process's executable, whose PT_INTERP names its dynamic linker. */
    static final String SELF_EXECUTABLE = "/proc/self/exe";

    /** Bounds the dynamic linker's list run, in seconds: it only maps files and reads headers. */
    static final long LISTING_TIMEOUT_SECONDS = 30;

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

        var initialEnvironment = LinuxNative.readInitialEnvironment();
        var environment = readEnvironment(System::getenv, initialEnvironment);
        verifyEnvironment(environment, (p, type) -> resolveTrusted(p, type, LinuxNative::statusOrNull, LinuxNative::readLink, true));

        UnaryOperator<String> trusted = p -> resolveTrusted(p, UnixFileType.REGULAR_FILE, LinuxNative::statusOrNull, LinuxNative::readLink);
        verifyBeforeLoading(path, initialEnvironment, trusted);

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
     * Resolves {@code path} the way the kernel would, with {@link UnixPathResolver}, checking
     * everything it passes through: every directory and the final object must be owned by root and
     * writable by neither group nor others, and every symbolic link must be owned by root (its
     * target is then resolved and checked in turn). Returns the resolved path, which contains no
     * symbolic links.
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

        Resolution resolution;
        try {
            resolution = UnixPathResolver.resolve(path, getStatus::apply, readLink::apply, status -> whyUntrusted(status) == null, uid -> uid == 0);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        return switch (resolution) {
            case Resolution.Resolved(var resolved, var type) -> {
                if (type != expectedType)
                    throw new SecurityException("'" + path + "' resolves to '" + resolved + "', which is a " + describe(type) + ", not a "
                            + describe(expectedType) + ".");
                yield resolved;
            }
            case Resolution.RootUnreadable() -> throw new SecurityException("'/' could not be examined.");
            case Resolution.Missing(var component) -> {
                if (allowMissing)
                    yield null;
                throw new SecurityException("'" + component + "' does not exist (resolving '" + path + "').");
            }
            case Resolution.NotADirectory(var component) ->
                    throw new SecurityException("'" + path + "' runs through '" + component + "', which is not a directory.");
            case Resolution.UntrustedComponent(var component, var status) -> throw new SecurityException("'" + component + "' " + whyUntrusted(status));
            case Resolution.UntrustedLink(var component, var status) -> throw new SecurityException("'" + component + "' is a symbolic link owned by uid "
                    + status.ownerId() + "; only links owned by root are followed (resolving '" + path + "').");
            case Resolution.TooManyLinks() ->
                    throw new SecurityException("'" + path + "' follows more than " + UnixPathResolver.MAX_SYMBOLIC_LINKS + " symbolic links.");
            case Resolution.UnreadableLink(var component) -> throw new SecurityException("'" + component + "' could not be read as a symbolic link.");
        };
    }

    // Why a directory or file may not be on the library's path, or null if it may: only root may change it.
    private static String whyUntrusted(UnixFileStatus status) {
        if (status.ownerId() != 0)
            return "is owned by uid " + status.ownerId() + "; the HkdfGuard native library and its dependencies are only trusted in locations owned by root.";

        if (status.groupWritable() || status.otherWritable())
            return "is writable by its group or by every user; the HkdfGuard native library and its dependencies are only trusted in locations only root can modify.";

        return null;
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
        // LD_LIBRARY_PATH check above already covers. A bare-named LD_PRELOAD object is also covered
        // by the dynamic linker's list run before loading (verifyBeforeLoading): it runs with the
        // startup LD_PRELOAD, so it reports the file each preloaded object was found in, and each
        // must pass the path checks. (Only a check: a preloaded object was mapped when the process
        // started, and its initializers have already run.)
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
     * Asks this process's own dynamic linker, in list mode, where it would find everything
     * {@code library} pulls in, and requires each of those files to pass the path checks - before
     * dlopen, so nothing that would fail them ever runs here (check 4 above).
     *
     * @param library            the verified library
     * @param initialEnvironment /proc/self/environ's block, or null if it could not be read
     * @param resolveTrusted     resolves a path, throwing unless it passes the path checks
     * @throws SecurityException the dynamic linker isn't trusted or can't say, or it would load an untrusted file
     */
    static void verifyBeforeLoading(String library, byte[] initialEnvironment, UnaryOperator<String> resolveTrusted) {
        String interpreter;
        try {
            interpreter = ElfDependencies.readInterpreter(SELF_EXECUTABLE);
        } catch (SecurityException | UncheckedIOException e) {
            throw new SecurityException("Could not read which dynamic linker this process runs under: " + messageOf(e), e);
        }
        if (interpreter == null)
            throw new SecurityException("This process has no dynamic linker (a statically linked executable), so it can't be asked what '" + library
                    + "' would load; refusing to load it.");

        String trustedInterpreter;
        try {
            trustedInterpreter = resolveTrusted.apply(interpreter);
        } catch (SecurityException | UncheckedIOException e) {
            throw new SecurityException("This process's dynamic linker '" + interpreter + "' is not trusted, so it can't be asked what '" + library
                    + "' would load: " + messageOf(e), e);
        }

        var output = listDependencies(trustedInterpreter, library, listingEnvironment(initialEnvironment));
        verifyListing(library, parseListing(library, output), resolveTrusted);
    }

    /**
     * The whole environment the dynamic linker's list mode runs with: the LD_LIBRARY_PATH and
     * LD_PRELOAD the process started with - what dlopen itself uses, since the linker reads them once
     * at startup - and nothing else. LD_AUDIT is left out: an audit module is code the list run would
     * execute, and its locations were already checked before this runs. Should the block name a
     * variable twice, the last value wins, as in the dynamic linker.
     *
     * @param initialEnvironment /proc/self/environ's NUL-separated block, or null if it could not be read
     * @throws SecurityException a value can't be passed on to a child process byte for byte
     */
    static Map<String, String> listingEnvironment(byte[] initialEnvironment) {
        var environment = new LinkedHashMap<String, String>();
        if (initialEnvironment == null)
            return environment;

        // A child's environment is encoded in the charset the JVM uses for the platform's strings;
        // a value that doesn't decode in it exactly would reach the list run altered, and the list
        // would describe some other search than dlopen's.
        var charset = childEnvironmentCharset();
        var start = 0;
        while (start < initialEnvironment.length) {
            var end = start;
            while (end < initialEnvironment.length && initialEnvironment[end] != 0)
                end++;
            for (var name : List.of(LIBRARY_PATH_VARIABLE, PRELOAD_VARIABLE)) {
                var prefix = (name + "=").getBytes(StandardCharsets.US_ASCII);
                if (end - start >= prefix.length && Arrays.equals(initialEnvironment, start, start + prefix.length, prefix, 0, prefix.length)) {
                    try {
                        environment.put(name, charset.newDecoder()
                                .onMalformedInput(CodingErrorAction.REPORT)
                                .onUnmappableCharacter(CodingErrorAction.REPORT)
                                .decode(ByteBuffer.wrap(initialEnvironment, start + prefix.length, end - start - prefix.length))
                                .toString());
                    } catch (CharacterCodingException e) {
                        throw new SecurityException("The " + name + " this process started with is not valid " + charset
                                + ", so the dynamic linker can't be asked what it would load under it; refusing to load the HkdfGuard native library.", e);
                    }
                }
            }
            start = end + 1;
        }
        return environment;
    }

    // The charset the JVM encodes a child process's environment in.
    private static Charset childEnvironmentCharset() {
        var name = System.getProperty("sun.jnu.encoding", System.getProperty("native.encoding"));
        try {
            return name == null ? Charset.defaultCharset() : Charset.forName(name);
        } catch (IllegalArgumentException e) {
            return Charset.defaultCharset();
        }
    }

    /**
     * Runs {@code interpreter --list library} with exactly {@code environment} - no shell, nothing
     * inherited - and returns what it printed. A run that fails or times out refuses the load.
     *
     * @throws SecurityException it could not be run, exited with a failure, or did not finish in time
     */
    static String listDependencies(String interpreter, String library, Map<String, String> environment) {
        var builder = new ProcessBuilder(interpreter, "--list", library);
        builder.environment().clear();
        builder.environment().putAll(environment);

        Process process;
        try {
            process = builder.start();
        } catch (IOException e) {
            throw new SecurityException("The dynamic linker '" + interpreter + "' could not be run to say what '" + library + "' would load ("
                    + e.getMessage() + "); refusing to load it.", e);
        }

        // Both pipes are drained at once, so neither can fill and stall the run.
        var stdout = drain(process.getInputStream());
        var stderr = drain(process.getErrorStream());
        try {
            process.getOutputStream().close();
            if (!process.waitFor(LISTING_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new SecurityException("The dynamic linker did not say within " + LISTING_TIMEOUT_SECONDS + " seconds what '" + library
                        + "' would load; refusing to load it.");
            }
            if (process.exitValue() != 0)
                throw new SecurityException("The dynamic linker could not say what '" + library + "' would load (exit status " + process.exitValue()
                        + ": " + stderr.join().strip() + "); refusing to load it.");
            return stdout.join();
        } catch (InterruptedException e) {
            process.destroyForcibly();
            Thread.currentThread().interrupt();
            throw new SecurityException("Interrupted while asking the dynamic linker what '" + library + "' would load; refusing to load it.", e);
        } catch (IOException | CompletionException e) {
            process.destroyForcibly();
            throw new SecurityException("Could not read what the dynamic linker said '" + library + "' would load (" + e.getMessage() + "); refusing to load it.", e);
        }
    }

    // Reads a child's output to the end on a thread of its own.
    private static CompletableFuture<String> drain(InputStream stream) {
        return CompletableFuture.supplyAsync(() -> {
            try (stream) {
                return new String(stream.readAllBytes(), StandardCharsets.UTF_8);
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }, task -> Thread.ofVirtual().start(task));
    }

    /**
     * Every file path in the output of the dynamic linker's list mode, in order. Its lines are
     * "\tname =&gt; /path (0xaddress)", "\t/path (0xaddress)" (the linker itself and preloaded
     * objects) and "\tname (0xaddress)" (the vDSO, which has no file). A name it couldn't find
     * ("=&gt; not found"), or any line in another form, refuses: what can't be read can't be checked.
     *
     * @param library the library that was listed, for messages
     * @param output  what the list run printed
     * @throws SecurityException a dependency can't be found, or a line can't be read
     */
    static List<String> parseListing(String library, String output) {
        final String notFound = " => not found";
        final String arrow = " => ";
        var paths = new ArrayList<String>();
        for (var rawLine : output.split("\n", -1)) {
            var line = rawLine.strip();
            if (line.isEmpty())
                continue;

            if (line.endsWith(notFound))
                throw new SecurityException("The dynamic linker can't find '" + line.substring(0, line.length() - notFound.length()) + "', which '" + library
                        + "' needs; refusing to load it.");

            var open = line.lastIndexOf(" (0x");
            if (open < 0 || !line.endsWith(")"))
                throw new SecurityException("The dynamic linker's list of what '" + library + "' would load has a line this loader doesn't understand ('" + line
                        + "'); refusing to load it.");

            var entry = line.substring(0, open);
            var at = entry.indexOf(arrow);
            if (at >= 0)
                entry = entry.substring(at + arrow.length());

            if (!entry.startsWith("/")) {
                if (entry.contains("/") || entry.contains(" "))
                    throw new SecurityException("The dynamic linker would load '" + entry + "' for '" + library + "', which is not an absolute path; refusing to load it.");
                continue; // the vDSO: in the kernel, not a file
            }
            paths.add(entry);
        }
        return List.copyOf(paths);
    }

    /**
     * Requires every path the dynamic linker's list mode reported to pass the path checks.
     *
     * @param library        the library that was listed, for messages
     * @param paths          what {@link #parseListing} returned
     * @param resolveTrusted resolves a path, throwing unless it passes the path checks
     * @throws SecurityException a path is not trusted; the first one is named
     */
    static void verifyListing(String library, List<String> paths, UnaryOperator<String> resolveTrusted) {
        for (var path : paths) {
            try {
                resolveTrusted.apply(path);
            } catch (SecurityException | UncheckedIOException e) {
                throw new SecurityException("Loading '" + library + "' would also load '" + path + "', which is not trusted; nothing was loaded: " + messageOf(e), e);
            }
        }
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
