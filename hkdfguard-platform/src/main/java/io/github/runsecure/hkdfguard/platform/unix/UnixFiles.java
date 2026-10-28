package io.github.runsecure.hkdfguard.platform.unix;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;

import io.github.runsecure.hkdfguard.platform.NativeCalls;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.util.Locale;

/**
 * The system calls the Linux and macOS path checks need that Java doesn't expose as such: the
 * owner, group, permissions and type of a path itself, never what a symbolic link points to, and a
 * symbolic link's stored target. Linux uses statx and readlink from the C library this JVM already
 * runs on, found through the linker's default lookup - matched by name before anything is
 * searched, so LD_LIBRARY_PATH cannot substitute it - and statx (glibc 2.28 or later) has one struct
 * layout on every architecture. macOS uses lstat and readlink from libSystem, named by absolute
 * path, on arm64 only, whose struct stat this reads. Bound only on first use, so inert elsewhere.
 */
@SuppressWarnings("restricted") // Native access is this class's purpose; the module requires --enable-native-access.
public final class UnixFiles {
    private static final String MAC_OS_LIB_SYSTEM = "/usr/lib/libSystem.B.dylib";

    private static final int AT_FDCWD = -100;
    private static final int AT_SYMLINK_NOFOLLOW = 0x100;

    // struct statx: stx_mask u32 @0, stx_uid u32 @20, stx_gid u32 @24, stx_mode u16 @28; 256 bytes.
    private static final int STATX_BUFFER_SIZE = 256;
    private static final int STATX_TYPE = 0x1;
    private static final int STATX_MODE = 0x2;
    private static final int STATX_UID = 0x8;
    private static final int STATX_GID = 0x10;
    private static final int STATX_REQUIRED = STATX_TYPE | STATX_MODE | STATX_UID | STATX_GID;

    // macOS arm64 struct stat: st_mode u16 @4, st_uid u32 @16, st_gid u32 @20; 144 bytes.
    private static final int STAT_BUFFER_SIZE = 256;

    private static final int FILE_TYPE_MASK = 0xF000; // S_IFMT
    private static final int REGULAR_FILE = 0x8000;   // S_IFREG
    private static final int DIRECTORY = 0x4000;      // S_IFDIR
    private static final int SYMBOLIC_LINK = 0xA000;  // S_IFLNK
    private static final int PERMISSION_MASK = 0x0FFF;

    private static final int ENOENT = 2;
    private static final int EACCES = 13;
    private static final int ENOTDIR = 20;
    private static final int EINVAL = 22;

    // Longer than PATH_MAX on either system (4096 on Linux, 1024 on macOS), so a full buffer means a
    // truncated target.
    private static final int LINK_BUFFER_SIZE = 4097;

    private static final Linker LINKER = Linker.nativeLinker();
    private static final Linker.Option CAPTURE_ERRNO = Linker.Option.captureCallState("errno");
    private static final MemoryLayout CAPTURE_LAYOUT = Linker.Option.captureStateLayout();
    private static final VarHandle ERRNO = CAPTURE_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("errno"));

    private UnixFiles() {
    }

    private static MethodHandle bind(SymbolLookup library, String name, FunctionDescriptor descriptor) {
        return NativeCalls.bind(library, "C library", name, descriptor, CAPTURE_ERRNO);
    }

    private static final class Linux {
        static final SymbolLookup LIBRARY = LINKER.defaultLookup();
        static final MethodHandle STATX = bind(LIBRARY, "statx", FunctionDescriptor.of(JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, ADDRESS));
        static final MethodHandle READLINK = bind(LIBRARY, "readlink", FunctionDescriptor.of(JAVA_LONG, ADDRESS, ADDRESS, JAVA_LONG));
    }

    private static final class MacOs {
        // By name: system libraries live in the dyld shared cache, not as files on disk.
        static final SymbolLookup LIBRARY = SymbolLookup.libraryLookup(MAC_OS_LIB_SYSTEM, Arena.global());
        static final MethodHandle LSTAT = bind(LIBRARY, "lstat", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle READLINK = bind(LIBRARY, "readlink", FunctionDescriptor.of(JAVA_LONG, ADDRESS, ADDRESS, JAVA_LONG));
    }

    private static boolean isLinux() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("linux");
    }

    /** Refuses an Intel Mac before anything is bound: its "lstat" symbol fills an older, different struct. */
    private static void requireAppleSilicon() {
        var arch = System.getProperty("os.arch", "");
        if (!arch.equals("aarch64") && !arch.equals("arm64"))
            throw new UnsupportedOperationException("Only Apple silicon Macs are supported; this process is " + arch + ".");
    }

    private static RuntimeException rethrow(Throwable t) {
        return NativeCalls.rethrow(t, "A system call failed.");
    }

    /**
     * Describes the path itself, never what a symbolic link points to.
     *
     * @return the status, or null when nothing is there (ENOENT or ENOTDIR)
     * @throws AccessDeniedException         this account may not look (EACCES)
     * @throws IOException                   the call failed for any other reason
     * @throws UnsupportedOperationException macOS on an Intel processor
     */
    public static UnixFileStatus statusOrNull(String path) throws IOException {
        var status = new UnixFileStatus[1];
        var errno = status(path, status);
        return switch (errno) {
            case 0 -> status[0];
            case ENOENT, ENOTDIR -> null;
            case EACCES -> throw new AccessDeniedException(path, null, "This account may not look up '" + path + "' (EACCES).");
            default -> throw new IOException("Could not look up '" + path + "' (errno " + errno + ").");
        };
    }

    /**
     * Whether something is at a path whose existence is only being probed.
     *
     * @return 0 if it exists, else the errno the status call failed with
     * @throws IOException                   statx succeeded without reporting what is asked of it
     * @throws UnsupportedOperationException macOS on an Intel processor
     */
    public static int probe(String path) throws IOException {
        return status(path, new UnixFileStatus[1]);
    }

    /**
     * readlink: a symbolic link's target, exactly as stored (possibly relative).
     *
     * @return the target, or null if the path isn't a symbolic link (or isn't there)
     * @throws AccessDeniedException this account may not read it (EACCES)
     * @throws IOException           readlink failed for any other reason
     */
    public static String readLink(String path) throws IOException {
        MethodHandle readlink;
        if (isLinux()) {
            readlink = Linux.READLINK;
        } else {
            requireAppleSilicon();
            readlink = MacOs.READLINK;
        }

        long length;
        int errno;
        byte[] target;
        try (var arena = Arena.ofConfined()) {
            var capture = arena.allocate(CAPTURE_LAYOUT);
            var buffer = arena.allocate(LINK_BUFFER_SIZE);
            length = (long) readlink.invokeExact(capture, arena.allocateFrom(path), buffer, (long) LINK_BUFFER_SIZE);
            errno = length < 0 ? (int) ERRNO.get(capture, 0L) : 0;
            target = length > 0 && length < LINK_BUFFER_SIZE ? buffer.asSlice(0, length).toArray(JAVA_BYTE) : new byte[0];
        } catch (Throwable t) {
            throw rethrow(t);
        }

        if (length < 0) {
            if (errno == EINVAL || errno == ENOENT || errno == ENOTDIR)
                return null;
            if (errno == EACCES)
                throw new AccessDeniedException(path, null, "This account may not read the symbolic link '" + path + "' (EACCES).");
            throw new IOException("readlink('" + path + "') failed with errno " + errno + ".");
        }
        if (length >= LINK_BUFFER_SIZE)
            throw new IOException("readlink('" + path + "') returned a target longer than PATH_MAX.");

        return new String(target, StandardCharsets.UTF_8);
    }

    // 0 with the status in result[0], or the errno.
    private static int status(String path, UnixFileStatus[] result) throws IOException {
        return isLinux() ? linuxStatus(path, result) : macOsStatus(path, result);
    }

    private static int linuxStatus(String path, UnixFileStatus[] result) throws IOException {
        int rc;
        int mask;
        int mode;
        int uid;
        int gid;
        try (var arena = Arena.ofConfined()) {
            var capture = arena.allocate(CAPTURE_LAYOUT);
            var buffer = arena.allocate(STATX_BUFFER_SIZE, 8);
            rc = (int) Linux.STATX.invokeExact(capture, AT_FDCWD, arena.allocateFrom(path), AT_SYMLINK_NOFOLLOW, STATX_REQUIRED, buffer);
            if (rc != 0)
                return (int) ERRNO.get(capture, 0L);

            mask = buffer.get(JAVA_INT, 0);
            uid = buffer.get(JAVA_INT, 20);
            gid = buffer.get(JAVA_INT, 24);
            mode = Short.toUnsignedInt(buffer.get(JAVA_SHORT, 28));
        } catch (Throwable t) {
            throw rethrow(t);
        }

        if ((mask & STATX_REQUIRED) != STATX_REQUIRED)
            throw new IOException("statx('" + path + "') did not report the file's type, mode and owner.");

        result[0] = decode(mode, uid, gid);
        return 0;
    }

    private static int macOsStatus(String path, UnixFileStatus[] result) {
        requireAppleSilicon();
        try (var arena = Arena.ofConfined()) {
            var capture = arena.allocate(CAPTURE_LAYOUT);
            var buffer = arena.allocate(STAT_BUFFER_SIZE, 8);
            if ((int) MacOs.LSTAT.invokeExact(capture, arena.allocateFrom(path), buffer) != 0)
                return (int) ERRNO.get(capture, 0L);

            result[0] = decode(Short.toUnsignedInt(buffer.get(JAVA_SHORT, 4)), buffer.get(JAVA_INT, 16), buffer.get(JAVA_INT, 20));
            return 0;
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /** A status from {@code st_mode} and the raw (unsigned) uid and gid. */
    static UnixFileStatus decode(int mode, int uid, int gid) {
        var type = switch (mode & FILE_TYPE_MASK) {
            case REGULAR_FILE -> UnixFileType.REGULAR_FILE;
            case DIRECTORY -> UnixFileType.DIRECTORY;
            case SYMBOLIC_LINK -> UnixFileType.SYMBOLIC_LINK;
            default -> UnixFileType.OTHER;
        };
        return new UnixFileStatus(Integer.toUnsignedLong(uid), Integer.toUnsignedLong(gid), mode & PERMISSION_MASK, type);
    }
}
