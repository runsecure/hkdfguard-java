package io.github.runsecure.hkdfguard.securefile;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_CHAR;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.nio.charset.StandardCharsets.UTF_16LE;

import io.github.runsecure.hkdfguard.platform.windows.WindowsSecurity;
import java.io.Closeable;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.file.AccessDeniedException;
import java.nio.file.NoSuchFileException;

/**
 * The Win32 calls {@link TrustedKeyFile} makes on Windows besides the security-descriptor and SID
 * ones it shares with the native library loader (WindowsSecurity), bound through the FFM API: the
 * full and long form of a path (GetFullPathNameW, GetLongPathNameW), the drive type, opening and
 * reading the file with read sharing only (CreateFileW, ReadFile), and the opened handle's final
 * path (GetFinalPathNameByHandleW: the file it actually refers to, after every symbolic link,
 * junction, mount point and substituted drive has been resolved, in long-name form). kernel32 is a
 * KnownDLL, always mapped from System32. Bound only on first use, so this class is inert off
 * Windows. 64-bit Windows only - the only Windows the JDK still supports.
 */
@SuppressWarnings("restricted") // Native access is this class's purpose; the module requires --enable-native-access.
final class WindowsNative {
    private static final int GENERIC_READ = 0x80000000;
    private static final int FILE_SHARE_READ = 0x1;
    private static final int OPEN_EXISTING = 3;
    private static final int FILE_ATTRIBUTE_NORMAL = 0x80;
    private static final int FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;
    // FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
    private static final int FINAL_PATH_FLAGS = 0;

    private static final int ERROR_FILE_NOT_FOUND = 2;
    private static final int ERROR_PATH_NOT_FOUND = 3;
    private static final int ERROR_ACCESS_DENIED = 5;
    private static final int ERROR_SHARING_VIOLATION = 32;

    // The longest path Windows supports, plus its terminator.
    private static final int MAX_PATH_CHARS = 32768;

    private static final Linker LINKER = Linker.nativeLinker();
    private static final Linker.Option CAPTURE_LAST_ERROR = Linker.Option.captureCallState("GetLastError");
    private static final MemoryLayout CAPTURE_LAYOUT = Linker.Option.captureStateLayout();
    private static final VarHandle LAST_ERROR = CAPTURE_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("GetLastError"));

    private WindowsNative() {
    }

    // --- Binding ---------------------------------------------------------------------------

    private static MethodHandle bind(SymbolLookup library, String name, FunctionDescriptor descriptor, Linker.Option... options) {
        var address = library.find(name).orElseThrow(() -> new UnsatisfiedLinkError("Windows export '" + name + "' not found."));
        return LINKER.downcallHandle(address, descriptor, options);
    }

    private static final class Kernel32 {
        static final SymbolLookup LIBRARY = SymbolLookup.libraryLookup("kernel32.dll", Arena.global());
        static final MethodHandle GET_FULL_PATH_NAME = bind(LIBRARY, "GetFullPathNameW",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, ADDRESS), CAPTURE_LAST_ERROR);
        static final MethodHandle GET_LONG_PATH_NAME = bind(LIBRARY, "GetLongPathNameW", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT));
        static final MethodHandle GET_DRIVE_TYPE = bind(LIBRARY, "GetDriveTypeW", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        static final MethodHandle CREATE_FILE = bind(LIBRARY, "CreateFileW",
                FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_INT, JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, ADDRESS), CAPTURE_LAST_ERROR);
        static final MethodHandle READ_FILE = bind(LIBRARY, "ReadFile",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT, ADDRESS, ADDRESS), CAPTURE_LAST_ERROR);
        static final MethodHandle CLOSE_HANDLE = bind(LIBRARY, "CloseHandle", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        static final MethodHandle GET_FINAL_PATH_NAME = bind(LIBRARY, "GetFinalPathNameByHandleW",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT, JAVA_INT), CAPTURE_LAST_ERROR);
    }

    private static RuntimeException rethrow(Throwable t) {
        if (t instanceof RuntimeException runtime)
            return runtime;
        if (t instanceof Error error)
            throw error;
        return new IllegalStateException("A Win32 call failed.", t);
    }

    // --- Paths -----------------------------------------------------------------------------

    /**
     * What .NET's Path.GetFullPath returns: GetFullPathNameW's absolute, normalized form, with every
     * 8.3 short name that exists on disk expanded to its long name. A short name for something that
     * doesn't exist stays short, and the final-path check then refuses it.
     *
     * @throws IOException the path can't be made absolute
     */
    static String fullPath(String path) throws IOException {
        String full;
        try (var arena = Arena.ofConfined()) {
            var capture = arena.allocate(CAPTURE_LAYOUT);
            var buffer = arena.allocate(JAVA_CHAR, MAX_PATH_CHARS);
            var length = (int) Kernel32.GET_FULL_PATH_NAME.invokeExact(capture, arena.allocateFrom(path, UTF_16LE), MAX_PATH_CHARS, buffer,
                    MemorySegment.NULL);
            if (length <= 0 || length >= MAX_PATH_CHARS)
                throw new IOException("Could not make '" + path + "' an absolute path (error " + (int) LAST_ERROR.get(capture, 0L) + ").");
            full = buffer.getString(0, UTF_16LE);
        } catch (IOException e) {
            throw e;
        } catch (Throwable t) {
            throw rethrow(t);
        }
        return full.indexOf('~') < 0 ? full : expandShortNames(full);
    }

    /**
     * Expands the longest leading part of {@code full} that exists, as .NET does: GetLongPathNameW
     * fails outright for a path whose last component is missing.
     */
    private static String expandShortNames(String full) {
        var prefix = full;
        var rest = "";
        while (true) {
            var expanded = longPathName(prefix);
            if (expanded != null)
                return expanded + rest;

            var separator = prefix.lastIndexOf('\\');
            // Stop at the root ("C:\" or "\\server\share\"): nothing left to expand.
            if (separator <= 2)
                return full;
            rest = prefix.substring(separator) + rest;
            prefix = prefix.substring(0, separator);
        }
    }

    private static String longPathName(String path) {
        try (var arena = Arena.ofConfined()) {
            var buffer = arena.allocate(JAVA_CHAR, MAX_PATH_CHARS);
            var length = (int) Kernel32.GET_LONG_PATH_NAME.invokeExact(arena.allocateFrom(path, UTF_16LE), buffer, MAX_PATH_CHARS);
            return length <= 0 || length >= MAX_PATH_CHARS ? null : buffer.getString(0, UTF_16LE);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /** GetDriveTypeW of a drive root such as "C:\". */
    static DriveType driveType(String root) {
        try (var arena = Arena.ofConfined()) {
            return DriveType.fromWin32((int) Kernel32.GET_DRIVE_TYPE.invokeExact(arena.allocateFrom(root, UTF_16LE)));
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    // --- The opened file -------------------------------------------------------------------

    /**
     * Opens a file for reading with read sharing only: refused if another process has it open for
     * writing, and no one can open it for writing while it is held.
     *
     * @throws NoSuchFileException   the file, or a folder in its path, doesn't exist
     * @throws AccessDeniedException this account may not read it (or it is a folder)
     * @throws IOException           another process has it open for writing, or it can't be opened
     */
    static OpenFile open(String path) throws IOException {
        MemorySegment handle;
        int error;
        try (var arena = Arena.ofConfined()) {
            var capture = arena.allocate(CAPTURE_LAYOUT);
            handle = (MemorySegment) Kernel32.CREATE_FILE.invokeExact(capture, arena.allocateFrom(path, UTF_16LE), GENERIC_READ, FILE_SHARE_READ,
                    MemorySegment.NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, MemorySegment.NULL);
            error = (int) LAST_ERROR.get(capture, 0L);
        } catch (Throwable t) {
            throw rethrow(t);
        }

        // INVALID_HANDLE_VALUE is -1.
        if (handle.address() != -1L && handle.address() != 0)
            return new OpenFile(handle);

        throw switch (error) {
            case ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND -> new NoSuchFileException(path, null, "Key file '" + path + "' was not found.");
            case ERROR_ACCESS_DENIED -> new AccessDeniedException(path, null, "This account may not read key file '" + path + "'.");
            case ERROR_SHARING_VIOLATION -> new IOException("Key file '" + path + "' is open for writing by another process.");
            default -> new IOException("Could not open key file '" + path + "' (error " + error + ").");
        };
    }

    /** A file opened by {@link #open}; closing it closes the handle. */
    static final class OpenFile implements Closeable {
        private final MemorySegment handle;
        private boolean closed;

        private OpenFile(MemorySegment handle) {
            this.handle = handle;
        }

        /**
         * GetFinalPathNameByHandleW: the path of the file this handle actually refers to.
         *
         * @throws IOException the path could not be read from the handle
         */
        String finalPath() throws IOException {
            var capacity = 512;
            while (true) {
                int length;
                int error;
                String path;
                try (var arena = Arena.ofConfined()) {
                    var capture = arena.allocate(CAPTURE_LAYOUT);
                    var buffer = arena.allocate(JAVA_CHAR, capacity);
                    length = (int) Kernel32.GET_FINAL_PATH_NAME.invokeExact(capture, handle, buffer, capacity, FINAL_PATH_FLAGS);
                    error = (int) LAST_ERROR.get(capture, 0L);
                    path = length > 0 && length < capacity ? buffer.getString(0, UTF_16LE) : null;
                } catch (Throwable t) {
                    throw rethrow(t);
                }

                if (length == 0)
                    throw new IOException("Could not read the opened key file's final path (error " + error + ").");
                if (path != null)
                    return path;

                // Too small: length is the size needed, terminator included.
                capacity = length;
            }
        }

        /**
         * The file's owner and DACL, read through this handle.
         *
         * @throws IOException the descriptor could not be read
         */
        WindowsSecurity.SecurityDescriptorInfo securityDescriptor() throws IOException {
            return WindowsSecurity.securityDescriptorOfHandle(handle);
        }

        /**
         * ReadFile: up to {@code length} bytes into {@code destination} at {@code offset}.
         *
         * @return the number of bytes read; 0 at the end of the file
         * @throws IOException the read failed
         */
        int read(byte[] destination, int offset, int length) throws IOException {
            if (length == 0)
                return 0;

            int ok;
            int error;
            int read;
            try (var arena = Arena.ofConfined()) {
                var capture = arena.allocate(CAPTURE_LAYOUT);
                var buffer = arena.allocate(length);
                var count = arena.allocate(JAVA_INT);
                ok = (int) Kernel32.READ_FILE.invokeExact(capture, handle, buffer, length, count, MemorySegment.NULL);
                error = (int) LAST_ERROR.get(capture, 0L);
                read = count.get(JAVA_INT, 0);
                if (ok != 0 && read > 0)
                    MemorySegment.copy(buffer, JAVA_BYTE, 0, destination, offset, read);
                // The off-heap copy is erased before the arena releases it.
                buffer.fill((byte) 0);
            } catch (Throwable t) {
                throw rethrow(t);
            }

            if (ok == 0)
                throw new IOException("Could not read the key file (error " + error + ").");
            return read;
        }

        @Override
        public void close() {
            if (closed)
                return;
            closed = true;
            try {
                var ignored = (int) Kernel32.CLOSE_HANDLE.invokeExact(handle);
            } catch (Throwable t) {
                throw rethrow(t);
            }
        }
    }
}
