package io.github.runsecure.hkdfguard.securefile;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_CHAR;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;
import static java.nio.charset.StandardCharsets.UTF_16LE;

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
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * The Win32 calls {@link TrustedKeyFile} makes on Windows, bound through the FFM API: the full and
 * long form of a path (GetFullPathNameW, GetLongPathNameW), the drive type, opening and reading the
 * file with read sharing only (CreateFileW, ReadFile), the opened handle's final path
 * (GetFinalPathNameByHandleW: the file it actually refers to, after every symbolic link, junction,
 * mount point and substituted drive has been resolved, in long-name form), file attributes, and the
 * owner and DACL of the opened handle (GetSecurityInfo) and of a folder by path
 * (GetNamedSecurityInfoW). kernel32 is a KnownDLL, always mapped from System32; advapi32 is loaded by
 * its absolute System32 path, never from the application directory or PATH. Each library is bound
 * only on first use, so this class is inert off Windows. 64-bit Windows only - the only Windows the
 * JDK still supports.
 */
@SuppressWarnings("restricted") // Native access is this class's purpose; the module requires --enable-native-access.
final class WindowsNative {
    static final int INVALID_FILE_ATTRIBUTES = -1;
    static final int FILE_ATTRIBUTE_REPARSE_POINT = 0x400;

    static final int ACCESS_ALLOWED_ACE_TYPE = 0x00;
    static final int ACCESS_DENIED_ACE_TYPE = 0x01;
    static final int ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06;
    static final int ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09;
    static final int ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0A;
    static final int ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0C;
    static final int INHERIT_ONLY_ACE = 0x08;

    private static final int GENERIC_READ = 0x80000000;
    private static final int FILE_SHARE_READ = 0x1;
    private static final int OPEN_EXISTING = 3;
    private static final int FILE_ATTRIBUTE_NORMAL = 0x80;
    private static final int FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;
    // FILE_NAME_NORMALIZED | VOLUME_NAME_DOS
    private static final int FINAL_PATH_FLAGS = 0;

    private static final int SE_FILE_OBJECT = 1;
    private static final int OWNER_SECURITY_INFORMATION = 0x1;
    private static final int DACL_SECURITY_INFORMATION = 0x4;
    private static final int SDDL_REVISION_1 = 1;

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
        static final MethodHandle GET_SYSTEM_DIRECTORY = bind(LIBRARY, "GetSystemDirectoryW", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT));
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
        static final MethodHandle GET_FILE_ATTRIBUTES = bind(LIBRARY, "GetFileAttributesW", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        static final MethodHandle LOCAL_FREE = bind(LIBRARY, "LocalFree", FunctionDescriptor.of(ADDRESS, ADDRESS));
        static final String SYSTEM_DIRECTORY = systemDirectory();
    }

    private static final class Advapi32 {
        static final SymbolLookup LIBRARY = SymbolLookup.libraryLookup(Path.of(Kernel32.SYSTEM_DIRECTORY, "advapi32.dll"), Arena.global());
        static final MethodHandle GET_SECURITY_INFO = bind(LIBRARY, "GetSecurityInfo",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
        static final MethodHandle GET_NAMED_SECURITY_INFO = bind(LIBRARY, "GetNamedSecurityInfoW",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
        static final MethodHandle CONVERT_SDDL_TO_SD = bind(LIBRARY, "ConvertStringSecurityDescriptorToSecurityDescriptorW",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS, ADDRESS), CAPTURE_LAST_ERROR);
        static final MethodHandle GET_SD_OWNER = bind(LIBRARY, "GetSecurityDescriptorOwner", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS));
        static final MethodHandle GET_SD_DACL = bind(LIBRARY, "GetSecurityDescriptorDacl", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
        static final MethodHandle GET_ACE = bind(LIBRARY, "GetAce", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS));
        static final MethodHandle CONVERT_SID_TO_STRING = bind(LIBRARY, "ConvertSidToStringSidW", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle CONVERT_STRING_TO_SID = bind(LIBRARY, "ConvertStringSidToSidW", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle LOOKUP_ACCOUNT_SID = bind(LIBRARY, "LookupAccountSidW",
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS, ADDRESS));
    }

    private static RuntimeException rethrow(Throwable t) {
        if (t instanceof RuntimeException runtime)
            return runtime;
        if (t instanceof Error error)
            throw error;
        return new IllegalStateException("A Win32 call failed.", t);
    }

    private static boolean isNull(MemorySegment pointer) {
        return pointer.address() == 0;
    }

    private static String readWideString(MemorySegment pointer) {
        return pointer.reinterpret(Long.MAX_VALUE).getString(0, UTF_16LE);
    }

    private static void localFree(MemorySegment pointer) {
        if (isNull(pointer))
            return;
        try {
            var ignored = (MemorySegment) Kernel32.LOCAL_FREE.invokeExact(pointer);
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    private static String systemDirectory() {
        try (var arena = Arena.ofConfined()) {
            var capacity = 1024;
            var buffer = arena.allocate(JAVA_CHAR, capacity);
            var length = (int) Kernel32.GET_SYSTEM_DIRECTORY.invokeExact(buffer, capacity);
            if (length <= 0 || length >= capacity)
                throw new IllegalStateException("GetSystemDirectoryW failed.");
            return buffer.getString(0, UTF_16LE);
        } catch (Throwable t) {
            throw rethrow(t);
        }
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

    /** GetFileAttributesW: the item's own attributes (a link is not followed), or {@link #INVALID_FILE_ATTRIBUTES}. */
    static int fileAttributes(String path) {
        try (var arena = Arena.ofConfined()) {
            return (int) Kernel32.GET_FILE_ATTRIBUTES.invokeExact(arena.allocateFrom(path, UTF_16LE));
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
        if (handle.address() != -1L && !isNull(handle))
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
        SecurityDescriptorInfo securityDescriptor() throws IOException {
            try (var arena = Arena.ofConfined()) {
                var descriptor = arena.allocate(ADDRESS);
                var error = (int) Advapi32.GET_SECURITY_INFO.invokeExact(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                        MemorySegment.NULL, MemorySegment.NULL, MemorySegment.NULL, MemorySegment.NULL, descriptor);
                if (error != 0)
                    throw new IOException("Could not read the opened key file's security descriptor (error " + error + ").");

                var sd = descriptor.get(ADDRESS, 0);
                try {
                    return parse(sd);
                } finally {
                    localFree(sd);
                }
            } catch (IOException e) {
                throw e;
            } catch (Throwable t) {
                throw rethrow(t);
            }
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

    // --- Security descriptors --------------------------------------------------------------

    /**
     * One ACE.
     *
     * @param type  its ACE type
     * @param flags its ACE flags (inheritance)
     * @param mask  the access mask it allows or denies
     * @param sid   its trustee's SID string, or null for an ACE type with no plain SID
     */
    record Ace(int type, int flags, int mask, String sid) {
    }

    /**
     * An item's owner and DACL.
     *
     * @param ownerSid           the owner's SID string, or null if the descriptor has no owner
     * @param grantsEveryoneFull true when there is no DACL (or a NULL one), which grants everyone full access
     * @param aces               the DACL's entries, in order
     */
    record SecurityDescriptorInfo(String ownerSid, boolean grantsEveryoneFull, List<Ace> aces) {
    }

    /**
     * The owner and DACL of a file or folder, by path.
     *
     * @throws AccessDeniedException this account may not read them
     * @throws IOException           they could not be read
     */
    static SecurityDescriptorInfo securityDescriptorOf(String path) throws IOException {
        try (var arena = Arena.ofConfined()) {
            var descriptor = arena.allocate(ADDRESS);
            var error = (int) Advapi32.GET_NAMED_SECURITY_INFO.invokeExact(arena.allocateFrom(path, UTF_16LE), SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, MemorySegment.NULL, MemorySegment.NULL, MemorySegment.NULL,
                    MemorySegment.NULL, descriptor);
            if (error == ERROR_ACCESS_DENIED)
                throw new AccessDeniedException(path, null, "This account may not read the permissions of '" + path + "'.");
            if (error != 0)
                throw new IOException("Could not read the security descriptor of '" + path + "' (error " + error + ").");

            var sd = descriptor.get(ADDRESS, 0);
            try {
                return parse(sd);
            } finally {
                localFree(sd);
            }
        } catch (IOException e) {
            throw e;
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /**
     * A security descriptor written in SDDL - for testing the policy against descriptors a real
     * file would be hard to give.
     *
     * @throws IllegalArgumentException the SDDL is invalid
     */
    static SecurityDescriptorInfo securityDescriptorFromSddl(String sddl) {
        try (var arena = Arena.ofConfined()) {
            var capture = arena.allocate(CAPTURE_LAYOUT);
            var descriptor = arena.allocate(ADDRESS);
            var ok = (int) Advapi32.CONVERT_SDDL_TO_SD.invokeExact(capture, arena.allocateFrom(sddl, UTF_16LE), SDDL_REVISION_1,
                    descriptor, MemorySegment.NULL);
            if (ok == 0)
                throw new IllegalArgumentException("Invalid SDDL (error " + (int) LAST_ERROR.get(capture, 0L) + "): " + sddl);

            var sd = descriptor.get(ADDRESS, 0);
            try {
                return parse(sd);
            } finally {
                localFree(sd);
            }
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    private static SecurityDescriptorInfo parse(MemorySegment sd) throws Throwable {
        try (var arena = Arena.ofConfined()) {
            var owner = arena.allocate(ADDRESS);
            var defaulted = arena.allocate(JAVA_INT);
            if ((int) Advapi32.GET_SD_OWNER.invokeExact(sd, owner, defaulted) == 0)
                throw new IOException("Could not read a security descriptor's owner.");
            var ownerPointer = owner.get(ADDRESS, 0);
            var ownerSid = isNull(ownerPointer) ? null : sidToString(ownerPointer);

            var present = arena.allocate(JAVA_INT);
            var dacl = arena.allocate(ADDRESS);
            if ((int) Advapi32.GET_SD_DACL.invokeExact(sd, present, dacl, defaulted) == 0)
                throw new IOException("Could not read a security descriptor's DACL.");
            var daclPointer = dacl.get(ADDRESS, 0);
            if (present.get(JAVA_INT, 0) == 0 || isNull(daclPointer))
                return new SecurityDescriptorInfo(ownerSid, true, List.of());

            // ACL header: AclRevision u8, Sbz1 u8, AclSize u16, AceCount u16 @4, Sbz2 u16.
            var aceCount = Short.toUnsignedInt(daclPointer.reinterpret(8).get(JAVA_SHORT, 4));
            var aces = new ArrayList<Ace>(aceCount);
            var acePointer = arena.allocate(ADDRESS);
            for (var i = 0; i < aceCount; i++) {
                if ((int) Advapi32.GET_ACE.invokeExact(daclPointer, i, acePointer) == 0)
                    throw new IOException("Could not read ACE " + i + " of a DACL.");

                // ACE_HEADER: AceType u8, AceFlags u8, AceSize u16; then, for the plain allow/deny
                // types and their callback forms, Mask u32 @4 and the SID @8.
                var ace = acePointer.get(ADDRESS, 0).reinterpret(8);
                var type = Byte.toUnsignedInt(ace.get(JAVA_BYTE, 0));
                var flags = Byte.toUnsignedInt(ace.get(JAVA_BYTE, 1));
                var size = Short.toUnsignedInt(ace.get(JAVA_SHORT, 2));
                var mask = ace.get(JAVA_INT, 4);
                var hasPlainSid = type == ACCESS_ALLOWED_ACE_TYPE || type == ACCESS_DENIED_ACE_TYPE
                        || type == ACCESS_ALLOWED_CALLBACK_ACE_TYPE || type == ACCESS_DENIED_CALLBACK_ACE_TYPE;
                var sid = hasPlainSid ? sidToString(ace.reinterpret(size).asSlice(8)) : null;
                aces.add(new Ace(type, flags, mask, sid));
            }
            return new SecurityDescriptorInfo(ownerSid, false, List.copyOf(aces));
        }
    }

    private static String sidToString(MemorySegment sid) throws Throwable {
        try (var arena = Arena.ofConfined()) {
            var result = arena.allocate(ADDRESS);
            if ((int) Advapi32.CONVERT_SID_TO_STRING.invokeExact(sid, result) == 0)
                throw new IOException("Could not read a SID.");
            var text = result.get(ADDRESS, 0);
            try {
                return readWideString(text);
            } finally {
                localFree(text);
            }
        }
    }

    /**
     * A SID string in its canonical form ("S-1-5-32-544"), as ConvertStringSidToSidW reads it - which
     * also accepts the SDDL aliases, such as "BA" - or null if it isn't a SID.
     */
    static String canonicalSid(String sid) {
        try (var arena = Arena.ofConfined()) {
            var binary = arena.allocate(ADDRESS);
            if ((int) Advapi32.CONVERT_STRING_TO_SID.invokeExact(arena.allocateFrom(sid, UTF_16LE), binary) == 0)
                return null;

            var sidPointer = binary.get(ADDRESS, 0);
            try {
                return sidToString(sidPointer);
            } finally {
                localFree(sidPointer);
            }
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    /** The account a SID maps to, as DOMAIN\name - or null if it maps to none here. */
    static String accountName(String sid) {
        try (var arena = Arena.ofConfined()) {
            var binary = arena.allocate(ADDRESS);
            if ((int) Advapi32.CONVERT_STRING_TO_SID.invokeExact(arena.allocateFrom(sid, UTF_16LE), binary) == 0)
                return null;

            var sidPointer = binary.get(ADDRESS, 0);
            try {
                var capacity = 256;
                var name = arena.allocate(JAVA_CHAR, capacity);
                var domain = arena.allocate(JAVA_CHAR, capacity);
                var nameLength = arena.allocateFrom(JAVA_INT, capacity);
                var domainLength = arena.allocateFrom(JAVA_INT, capacity);
                var use = arena.allocate(JAVA_INT);
                var ok = (int) Advapi32.LOOKUP_ACCOUNT_SID.invokeExact(MemorySegment.NULL, sidPointer, name, nameLength, domain, domainLength, use);
                if (ok == 0)
                    return null;

                var domainName = domain.getString(0, UTF_16LE);
                var accountName = name.getString(0, UTF_16LE);
                return domainName.isEmpty() ? accountName : domainName + "\\" + accountName;
            } finally {
                localFree(sidPointer);
            }
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }
}
