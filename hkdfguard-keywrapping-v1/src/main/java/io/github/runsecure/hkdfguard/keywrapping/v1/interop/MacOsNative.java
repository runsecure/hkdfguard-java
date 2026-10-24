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

/**
 * The macOS system calls {@link MacOsNativeLibraryLoader}'s checks rely on, bound through the FFM
 * API: lstat for ownership, permissions and type; geteuid and getpwuid_r for the user's home; dlopen/dlsym/dlclose, and dladdr for
 * which file dyld really loaded; and the Security framework's static code signature check. Every
 * library is named by absolute path. Bound only on first use, so inert off macOS.
 */
@SuppressWarnings("restricted") // Native access is this class's purpose; the module requires --enable-native-access.
final class MacOsNative {
    private static final String LIB_SYSTEM = "/usr/lib/libSystem.B.dylib";
    private static final String CORE_FOUNDATION = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation";
    private static final String SECURITY = "/System/Library/Frameworks/Security.framework/Security";

    // struct stat on arm64, the only architecture the loader runs on (it refuses x64 first): st_dev
    // int32 @0, st_mode uint16 @4, st_nlink uint16 @6, st_ino uint64 @8, st_uid uint32 @16, st_gid
    // uint32 @20. sizeof(struct stat) is 144; the buffer is larger to be safe.
    private static final int STAT_BUFFER_SIZE = 256;
    private static final int MODE_OFFSET = 4;
    private static final int UID_OFFSET = 16;
    private static final int GID_OFFSET = 20;

    private static final int FILE_TYPE_MASK = 0xF000; // S_IFMT
    private static final int REGULAR_FILE = 0x8000;   // S_IFREG
    private static final int DIRECTORY = 0x4000;      // S_IFDIR
    private static final int SYMBOLIC_LINK = 0xA000;  // S_IFLNK

    private static final int RTLD_NOW = 0x2;
    private static final int RTLD_LOCAL = 0x4;

    private static final int CF_STRING_ENCODING_UTF8 = 0x08000100;
    private static final int SEC_CS_CHECK_ALL_ARCHITECTURES = 1;
    private static final int SEC_CS_STRICT_VALIDATE = 1 << 4;

    private static final Linker LINKER = Linker.nativeLinker();
    private static final Linker.Option CAPTURE_ERRNO = Linker.Option.captureCallState("errno");
    private static final MemoryLayout CAPTURE_LAYOUT = Linker.Option.captureStateLayout();
    private static final VarHandle ERRNO = CAPTURE_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("errno"));

    private MacOsNative() {
    }

    private static MethodHandle bind(SymbolLookup library, String name, FunctionDescriptor descriptor, Linker.Option... options) {
        var address = library.find(name).orElseThrow(() -> new UnsatisfiedLinkError("macOS export '" + name + "' not found."));
        return LINKER.downcallHandle(address, descriptor, options);
    }

    private static final class LibSystem {
        // By name: system libraries live in the dyld shared cache, not as files on disk.
        static final SymbolLookup LIBRARY = SymbolLookup.libraryLookup(LIB_SYSTEM, Arena.global());
        static final MethodHandle LSTAT = bind(LIBRARY, "lstat", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS), CAPTURE_ERRNO);
        static final MethodHandle GETEUID = bind(LIBRARY, "geteuid", FunctionDescriptor.of(JAVA_INT));
        static final MethodHandle DLOPEN = bind(LIBRARY, "dlopen", FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_INT));
        static final MethodHandle DLSYM = bind(LIBRARY, "dlsym", FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS));
        static final MethodHandle DLCLOSE = bind(LIBRARY, "dlclose", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        static final MethodHandle DLERROR = bind(LIBRARY, "dlerror", FunctionDescriptor.of(ADDRESS));
        static final MethodHandle DLADDR = bind(LIBRARY, "dladdr", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle GETPWUID_R = bind(LIBRARY, "getpwuid_r",
                FunctionDescriptor.of(JAVA_INT, JAVA_INT, ADDRESS, ADDRESS, JAVA_LONG, ADDRESS));
    }

    private static final class Frameworks {
        static final SymbolLookup CF = SymbolLookup.libraryLookup(CORE_FOUNDATION, Arena.global());
        static final SymbolLookup SEC = SymbolLookup.libraryLookup(SECURITY, Arena.global());
        static final MethodHandle CF_URL_CREATE = bind(CF, "CFURLCreateFromFileSystemRepresentation",
                FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS, JAVA_LONG, JAVA_BYTE));
        static final MethodHandle CF_STRING_CREATE = bind(CF, "CFStringCreateWithCString", FunctionDescriptor.of(ADDRESS, ADDRESS, ADDRESS, JAVA_INT));
        static final MethodHandle CF_RELEASE = bind(CF, "CFRelease", FunctionDescriptor.ofVoid(ADDRESS));
        static final MethodHandle STATIC_CODE_CREATE = bind(SEC, "SecStaticCodeCreateWithPath", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS));
        static final MethodHandle REQUIREMENT_CREATE = bind(SEC, "SecRequirementCreateWithString", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS));
        static final MethodHandle CHECK_VALIDITY = bind(SEC, "SecStaticCodeCheckValidity", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS));
    }

    private static RuntimeException rethrow(Throwable t) {
        if (t instanceof RuntimeException runtime)
            return runtime;
        if (t instanceof Error error)
            throw error;
        return new IllegalStateException("A macOS system call failed.", t);
    }

    private static boolean isNull(MemorySegment pointer) {
        return pointer.address() == 0;
    }

    /** lstat's result for a path whose existence is only being probed: 0 if it exists, else the errno. */
    static int probe(String path) {
        try (var arena = Arena.ofConfined()) {
            var capture = arena.allocate(CAPTURE_LAYOUT);
            var result = (int) LibSystem.LSTAT.invokeExact(capture, arena.allocateFrom(path), arena.allocate(STAT_BUFFER_SIZE, 8));
            return result == 0 ? 0 : (int) ERRNO.get(capture, 0L);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /**
     * lstat: describes the path itself, never what a symbolic link points to.
     *
     * @throws UncheckedIOException lstat failed
     */
    static UnixFileStatus status(String path) {
        try (var arena = Arena.ofConfined()) {
            var capture = arena.allocate(CAPTURE_LAYOUT);
            var buffer = arena.allocate(STAT_BUFFER_SIZE, 8);
            if ((int) LibSystem.LSTAT.invokeExact(capture, arena.allocateFrom(path), buffer) != 0)
                throw new UncheckedIOException(new IOException("lstat('" + path + "') failed with errno " + (int) ERRNO.get(capture, 0L) + "."));

            var mode = Short.toUnsignedInt(buffer.get(JAVA_SHORT, MODE_OFFSET));
            var type = switch (mode & FILE_TYPE_MASK) {
                case REGULAR_FILE -> UnixFileType.REGULAR_FILE;
                case DIRECTORY -> UnixFileType.DIRECTORY;
                case SYMBOLIC_LINK -> UnixFileType.SYMBOLIC_LINK;
                default -> UnixFileType.OTHER;
            };
            return new UnixFileStatus(Integer.toUnsignedLong(buffer.get(JAVA_INT, UID_OFFSET)),
                    Integer.toUnsignedLong(buffer.get(JAVA_INT, GID_OFFSET)), UnixFileStatus.permissionsFromMode(mode), type);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    // struct passwd on arm64 (pwd.h): pw_name @0, pw_passwd @8, pw_uid @16, pw_gid @20, pw_change @24,
    // pw_class @32, pw_gecos @40, pw_dir @48, pw_shell @56, pw_expire @64; 72 bytes.
    private static final int PASSWD_SIZE = 72;
    private static final int PASSWD_DIR_OFFSET = 48;
    private static final int ERANGE = 34;

    /**
     * This process's effective user's home directory from the account database (getpwuid_r), or
     * null if there's no entry or it can't be read. Unlike the user.home property - which a
     * {@code -Duser.home} on the command line overrides - whoever launches the process can't
     * redirect it.
     */
    static String accountHomeDirectory() {
        try (var arena = Arena.ofConfined()) {
            var uid = (int) LibSystem.GETEUID.invokeExact();
            var passwd = arena.allocate(PASSWD_SIZE, 8);
            var result = arena.allocate(ADDRESS);
            for (long size = 4096; size <= 1 << 20; size *= 2) {
                var buffer = arena.allocate(size, 8);
                var rc = (int) LibSystem.GETPWUID_R.invokeExact(uid, passwd, buffer, size, result);
                if (rc == ERANGE)
                    continue;
                if (rc != 0 || isNull(result.get(ADDRESS, 0)))
                    return null;
                var directory = passwd.get(ADDRESS, PASSWD_DIR_OFFSET);
                return isNull(directory) ? null : directory.reinterpret(Long.MAX_VALUE).getString(0, StandardCharsets.UTF_8);
            }
            return null;
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static long effectiveUserId() {
        try {
            return Integer.toUnsignedLong((int) LibSystem.GETEUID.invokeExact());
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /** dlopen of an absolute path; null with {@code error} set if it failed. */
    static MemorySegment open(String path, StringBuilder error) {
        try (var arena = Arena.ofConfined()) {
            var handle = (MemorySegment) LibSystem.DLOPEN.invokeExact(arena.allocateFrom(path), RTLD_NOW | RTLD_LOCAL);
            if (!isNull(handle))
                return handle;

            var message = (MemorySegment) LibSystem.DLERROR.invokeExact();
            error.append(isNull(message) ? "unknown error" : message.reinterpret(Long.MAX_VALUE).getString(0, StandardCharsets.UTF_8));
            return null;
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /** dlsym: the export's address, or null. */
    static MemorySegment symbol(MemorySegment handle, String name) {
        try (var arena = Arena.ofConfined()) {
            var address = (MemorySegment) LibSystem.DLSYM.invokeExact(handle, arena.allocateFrom(name));
            return isNull(address) ? null : address;
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    static void close(MemorySegment handle) {
        try {
            var ignored = (int) LibSystem.DLCLOSE.invokeExact(handle);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /**
     * dladdr: the file dyld actually mapped the code at {@code address} from, or null if dyld
     * doesn't know the address. This is what was loaded, as opposed to what was asked for.
     */
    static String imagePath(MemorySegment address) {
        try (var arena = Arena.ofConfined()) {
            // Dl_info: dli_fname, dli_fbase, dli_sname, dli_saddr - four pointers.
            var info = arena.allocate(ADDRESS.byteSize() * 4, 8);
            if ((int) LibSystem.DLADDR.invokeExact(address, info) == 0)
                return null;

            var fileName = info.get(ADDRESS, 0);
            return isNull(fileName) ? null : fileName.reinterpret(Long.MAX_VALUE).getString(0, StandardCharsets.UTF_8);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /**
     * SecStaticCodeCheckValidity against {@code requirementText}, for every architecture in the
     * file, with strict validation.
     *
     * @return 0 (errSecSuccess) if valid and satisfied, otherwise the failing OSStatus
     */
    static int checkCodeSignature(String path, String requirementText) {
        var url = MemorySegment.NULL;
        var code = MemorySegment.NULL;
        var requirementString = MemorySegment.NULL;
        var requirement = MemorySegment.NULL;
        try (var arena = Arena.ofConfined()) {
            var pathBytes = path.getBytes(StandardCharsets.UTF_8);
            var pathSegment = arena.allocate(pathBytes.length + 1L);
            MemorySegment.copy(pathBytes, 0, pathSegment, JAVA_BYTE, 0, pathBytes.length);
            url = (MemorySegment) Frameworks.CF_URL_CREATE.invokeExact(MemorySegment.NULL, pathSegment, (long) pathBytes.length, (byte) 0);
            if (isNull(url))
                return -1;

            var out = arena.allocate(ADDRESS);
            var status = (int) Frameworks.STATIC_CODE_CREATE.invokeExact(url, 0, out);
            code = out.get(ADDRESS, 0);
            if (status != 0)
                return status;

            requirementString = (MemorySegment) Frameworks.CF_STRING_CREATE.invokeExact(MemorySegment.NULL, arena.allocateFrom(requirementText),
                    CF_STRING_ENCODING_UTF8);
            if (isNull(requirementString))
                return -1;

            status = (int) Frameworks.REQUIREMENT_CREATE.invokeExact(requirementString, 0, out);
            requirement = out.get(ADDRESS, 0);
            if (status != 0)
                return status;

            return (int) Frameworks.CHECK_VALIDITY.invokeExact(code, SEC_CS_CHECK_ALL_ARCHITECTURES | SEC_CS_STRICT_VALIDATE, requirement);
        } catch (Throwable t) {
            throw rethrow(t);
        } finally {
            for (var reference : new MemorySegment[] {requirement, requirementString, code, url})
                release(reference);
        }
    }

    private static void release(MemorySegment reference) {
        if (isNull(reference))
            return;
        try {
            Frameworks.CF_RELEASE.invokeExact(reference);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }
}
