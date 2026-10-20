package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * The Linux system calls {@link LinuxNativeLibraryLoader}'s checks rely on, bound through the FFM
 * API: statx (without following symbolic links) for ownership, permissions and type; readlink;
 * dladdr for which file the dynamic linker really mapped; and dlopen(RTLD_NOLOAD) with dlinfo for
 * where an already-loaded dependency came from - the same calls the .NET port's LinuxNative makes.
 * Every function is glibc's (2.34 or later, which the native package itself requires), found
 * through the linker's default lookup: the C library this JVM is already running on, matched by
 * name before anything is searched, so LD_LIBRARY_PATH cannot substitute it. Bound only on first
 * use, so inert off Linux.
 */
@SuppressWarnings("restricted") // Native access is this class's purpose; the module requires --enable-native-access.
final class LinuxNative {
    private static final int AT_FDCWD = -100;
    private static final int AT_SYMLINK_NOFOLLOW = 0x100;

    // struct statx has one layout on every architecture: stx_mask u32 @0, stx_uid u32 @20,
    // stx_gid u32 @24, stx_mode u16 @28. sizeof(struct statx) is 256.
    private static final int STATX_BUFFER_SIZE = 256;
    private static final int MASK_OFFSET = 0;
    private static final int UID_OFFSET = 20;
    private static final int GID_OFFSET = 24;
    private static final int MODE_OFFSET = 28;
    private static final int STATX_TYPE = 0x1;
    private static final int STATX_MODE = 0x2;
    private static final int STATX_UID = 0x8;
    private static final int STATX_GID = 0x10;
    private static final int STATX_REQUIRED = STATX_TYPE | STATX_MODE | STATX_UID | STATX_GID;

    private static final int FILE_TYPE_MASK = 0xF000; // S_IFMT
    private static final int REGULAR_FILE = 0x8000;   // S_IFREG
    private static final int DIRECTORY = 0x4000;      // S_IFDIR
    private static final int SYMBOLIC_LINK = 0xA000;  // S_IFLNK

    private static final int ENOENT = 2;
    private static final int ENOTDIR = 20;
    private static final int EINVAL = 22;

    // Longer than PATH_MAX (4096), so a full buffer means a truncated target.
    private static final int LINK_BUFFER_SIZE = 4097;

    private static final int RTLD_LAZY = 0x1;
    private static final int RTLD_NOLOAD = 0x4;
    private static final int RTLD_DI_LINKMAP = 2;

    private static final Linker LINKER = Linker.nativeLinker();
    private static final Linker.Option CAPTURE_ERRNO = Linker.Option.captureCallState("errno");
    private static final MemoryLayout CAPTURE_LAYOUT = Linker.Option.captureStateLayout();
    private static final VarHandle ERRNO = CAPTURE_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("errno"));

    private LinuxNative() {
    }

    private static final class LibC {
        static final SymbolLookup LIBRARY = LINKER.defaultLookup();
        static final MethodHandle STATX = bind("statx", FunctionDescriptor.of(JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, ADDRESS), CAPTURE_ERRNO);
        static final MethodHandle READLINK = bind("readlink", FunctionDescriptor.of(JAVA_LONG, ADDRESS, ADDRESS, JAVA_LONG), CAPTURE_ERRNO);
        static final MethodHandle DLADDR = bind("dladdr", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle DLOPEN = bind("dlopen", FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_INT));
        static final MethodHandle DLINFO = bind("dlinfo", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS));
        static final MethodHandle DLCLOSE = bind("dlclose", FunctionDescriptor.of(JAVA_INT, ADDRESS));

        private static MethodHandle bind(String name, FunctionDescriptor descriptor, Linker.Option... options) {
            var address = LIBRARY.find(name).orElseThrow(() -> new UnsatisfiedLinkError("C library export '" + name + "' not found."));
            return LINKER.downcallHandle(address, descriptor, options);
        }
    }

    private static RuntimeException rethrow(Throwable t) {
        if (t instanceof RuntimeException runtime)
            return runtime;
        if (t instanceof Error error)
            throw error;
        return new IllegalStateException("A Linux system call failed.", t);
    }

    private static boolean isNull(MemorySegment pointer) {
        return pointer.address() == 0;
    }

    private static String cString(MemorySegment pointer) {
        return isNull(pointer) ? null : pointer.reinterpret(Long.MAX_VALUE).getString(0, StandardCharsets.UTF_8);
    }

    private static UncheckedIOException ioFailure(String message) {
        return new UncheckedIOException(message, new IOException(message));
    }

    /**
     * Describes the path itself, never what a symbolic link points to.
     *
     * @return the status, or null when nothing is there (ENOENT or ENOTDIR)
     * @throws UncheckedIOException statx failed for any other reason, such as EACCES
     */
    static UnixFileStatus statusOrNull(String path) {
        var status = new UnixFileStatus[1];
        var errno = tryGetStatus(path, status);
        if (errno == 0)
            return status[0];
        if (errno == ENOENT || errno == ENOTDIR)
            return null;

        throw ioFailure("statx('" + path + "') failed with errno " + errno + ".");
    }

    /** The errno of a failed statx on a path whose existence is only being probed; 0 if it exists. */
    static int probe(String path) {
        return tryGetStatus(path, new UnixFileStatus[1]);
    }

    private static int tryGetStatus(String path, UnixFileStatus[] result) {
        try (var arena = Arena.ofConfined()) {
            var capture = arena.allocate(CAPTURE_LAYOUT);
            var buffer = arena.allocate(STATX_BUFFER_SIZE, 8);
            var rc = (int) LibC.STATX.invokeExact(capture, AT_FDCWD, arena.allocateFrom(path), AT_SYMLINK_NOFOLLOW, STATX_REQUIRED, buffer);
            if (rc != 0)
                return (int) ERRNO.get(capture, 0L);

            if ((buffer.get(JAVA_INT, MASK_OFFSET) & STATX_REQUIRED) != STATX_REQUIRED)
                throw ioFailure("statx('" + path + "') did not report the file's type, mode and owner.");

            var mode = Short.toUnsignedInt(buffer.get(JAVA_SHORT, MODE_OFFSET));
            var type = switch (mode & FILE_TYPE_MASK) {
                case REGULAR_FILE -> UnixFileType.REGULAR_FILE;
                case DIRECTORY -> UnixFileType.DIRECTORY;
                case SYMBOLIC_LINK -> UnixFileType.SYMBOLIC_LINK;
                default -> UnixFileType.OTHER;
            };
            result[0] = new UnixFileStatus(Integer.toUnsignedLong(buffer.get(JAVA_INT, UID_OFFSET)),
                    Integer.toUnsignedLong(buffer.get(JAVA_INT, GID_OFFSET)), UnixFileStatus.permissionsFromMode(mode), type);
            return 0;
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /**
     * readlink: a symbolic link's target, exactly as stored (possibly relative).
     *
     * @return the target, or null if the path isn't a symbolic link (or isn't there)
     * @throws UncheckedIOException readlink failed for any other reason
     */
    static String readLink(String path) {
        try (var arena = Arena.ofConfined()) {
            var capture = arena.allocate(CAPTURE_LAYOUT);
            var buffer = arena.allocate(LINK_BUFFER_SIZE);
            var length = (long) LibC.READLINK.invokeExact(capture, arena.allocateFrom(path), buffer, (long) LINK_BUFFER_SIZE);
            if (length < 0) {
                var errno = (int) ERRNO.get(capture, 0L);
                if (errno == EINVAL || errno == ENOENT || errno == ENOTDIR)
                    return null;
                throw ioFailure("readlink('" + path + "') failed with errno " + errno + ".");
            }
            if (length >= LINK_BUFFER_SIZE)
                throw ioFailure("readlink('" + path + "') returned a target longer than PATH_MAX.");

            var bytes = buffer.asSlice(0, length).toArray(JAVA_BYTE);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Throwable t) {
            throw rethrow(t);
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
