package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static io.github.runsecure.hkdfguard.platform.NativeCalls.isNull;
import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;

import io.github.runsecure.hkdfguard.platform.NativeCalls;
import io.github.runsecure.hkdfguard.platform.unix.UnixFileStatus;
import io.github.runsecure.hkdfguard.platform.unix.UnixFiles;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The Linux system calls {@link LinuxNativeLibraryLoader}'s checks rely on, bound through the FFM
 * API: statx (without following symbolic links) for ownership, permissions and type, and readlink,
 * both hkdfguard-platform's UnixFiles, shared with the key-file checks;
 * dladdr for which file the dynamic linker really mapped; and dlopen(RTLD_NOLOAD) with dlinfo for
 * where an already-loaded dependency came from - the same calls the .NET port's LinuxNative makes.
 * Every function is glibc's (2.34 or later, which the native package itself requires), found
 * through the linker's default lookup: the C library this JVM is already running on, matched by
 * name before anything is searched, so LD_LIBRARY_PATH cannot substitute it. Bound only on first
 * use, so inert off Linux.
 */
@SuppressWarnings("restricted") // Native access is this class's purpose; the module requires --enable-native-access.
final class LinuxNative {
    private static final int RTLD_LAZY = 0x1;
    private static final int RTLD_NOLOAD = 0x4;
    private static final int RTLD_DI_LINKMAP = 2;

    private static final Linker LINKER = Linker.nativeLinker();

    private LinuxNative() {
    }

    private static final class LibC {
        static final SymbolLookup LIBRARY = LINKER.defaultLookup();
        static final MethodHandle DLADDR = bind("dladdr", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle DLOPEN = bind("dlopen", FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_INT));
        static final MethodHandle DLINFO = bind("dlinfo", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS));
        static final MethodHandle DLCLOSE = bind("dlclose", FunctionDescriptor.of(JAVA_INT, ADDRESS));

        private static MethodHandle bind(String name, FunctionDescriptor descriptor, Linker.Option... options) {
            return NativeCalls.bind(LIBRARY, "C library", name, descriptor, options);
        }
    }

    private static RuntimeException rethrow(Throwable t) {
        return NativeCalls.rethrow(t, "A Linux system call failed.");
    }

    private static String cString(MemorySegment pointer) {
        return isNull(pointer) ? null : pointer.reinterpret(Long.MAX_VALUE).getString(0, StandardCharsets.UTF_8);
    }

    /**
     * Describes the path itself, never what a symbolic link points to.
     *
     * @return the status, or null when nothing is there (ENOENT or ENOTDIR)
     * @throws UncheckedIOException statx failed for any other reason, such as EACCES
     */
    static UnixFileStatus statusOrNull(String path) {
        try {
            return UnixFiles.statusOrNull(path);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** The errno of a failed statx on a path whose existence is only being probed; 0 if it exists. */
    static int probe(String path) {
        try {
            return UnixFiles.probe(path);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * readlink: a symbolic link's target, exactly as stored (possibly relative).
     *
     * @return the target, or null if the path isn't a symbolic link (or isn't there)
     * @throws UncheckedIOException readlink failed for any other reason
     */
    static String readLink(String path) {
        try {
            return UnixFiles.readLink(path);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /**
     * dladdr: the path the dynamic linker recorded for the object containing {@code address}, or
     * null if it doesn't know the address.
     */
    static String imagePath(MemorySegment address) {
        try (var arena = Arena.ofConfined()) {
            // Dl_info: dli_fname, dli_fbase, dli_sname, dli_saddr - four pointers.
            var info = arena.allocate(ADDRESS.byteSize() * 4, 8);
            if ((int) LibC.DLADDR.invokeExact(address, info) == 0)
                return null;

            return cString(info.get(ADDRESS, 0));
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /**
     * The path the dynamic linker recorded for the already-loaded object it would bind
     * {@code soname} to, or null if no such object is loaded. Never loads anything.
     */
    static String loadedPath(String soname) {
        try (var arena = Arena.ofConfined()) {
            var handle = (MemorySegment) LibC.DLOPEN.invokeExact(arena.allocateFrom(soname), RTLD_LAZY | RTLD_NOLOAD);
            if (isNull(handle))
                return null;

            try {
                // struct link_map: l_addr, l_name, ... - l_name is the second pointer.
                var mapOut = arena.allocate(ADDRESS);
                if ((int) LibC.DLINFO.invokeExact(handle, RTLD_DI_LINKMAP, mapOut) != 0)
                    return null;

                var map = mapOut.get(ADDRESS, 0);
                if (isNull(map))
                    return null;

                return cString(map.reinterpret(ADDRESS.byteSize() * 2).get(ADDRESS, ADDRESS.byteSize()));
            } finally {
                // RTLD_NOLOAD still took a reference; give it back.
                var ignored = (int) LibC.DLCLOSE.invokeExact(handle);
            }
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /**
     * The process's environment as it was at exec, which is what the dynamic linker read, or null
     * if /proc/self/environ can't be read.
     */
    static byte[] readInitialEnvironment() {
        try {
            return Files.readAllBytes(Path.of("/proc/self/environ"));
        } catch (IOException | SecurityException e) {
            return null;
        }
    }
}
