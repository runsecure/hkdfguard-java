package io.github.runsecure.hkdfguard.platform.windows;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_CHAR;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_SHORT;
import static java.nio.charset.StandardCharsets.UTF_16LE;

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
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * The Win32 calls that decide whether a path can be trusted, bound through the FFM API: an item's
 * own file attributes (GetFileAttributesW), the owner and DACL of a file or folder by path
 * (GetNamedSecurityInfoW) or through an open handle (GetSecurityInfo), and SID conversion and
 * lookup. kernel32 is a KnownDLL, always mapped from System32; advapi32 is loaded by its absolute
 * System32 path, never from the application directory or PATH. Each library is bound only on first
 * use, so this class is inert off Windows. 64-bit Windows only - the only Windows the JDK still
 * supports.
 */
@SuppressWarnings("restricted") // Native access is this class's purpose; the module requires --enable-native-access.
public final class WindowsSecurity {
    /** What GetFileAttributesW returns when the item can't be examined: every bit set. */
    public static final int INVALID_FILE_ATTRIBUTES = -1;
    public static final int FILE_ATTRIBUTE_REPARSE_POINT = 0x400;

    public static final int ACCESS_ALLOWED_ACE_TYPE = 0x00;
    public static final int ACCESS_DENIED_ACE_TYPE = 0x01;
    public static final int ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06;
    public static final int ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09;
    public static final int ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0A;
    public static final int ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0C;
    public static final int INHERIT_ONLY_ACE = 0x08;

    private static final int SE_FILE_OBJECT = 1;
    private static final int OWNER_SECURITY_INFORMATION = 0x1;
    private static final int DACL_SECURITY_INFORMATION = 0x4;
    private static final int SDDL_REVISION_1 = 1;

    private static final int ERROR_ACCESS_DENIED = 5;

    private static final Linker LINKER = Linker.nativeLinker();
    private static final Linker.Option CAPTURE_LAST_ERROR = Linker.Option.captureCallState("GetLastError");
    private static final MemoryLayout CAPTURE_LAYOUT = Linker.Option.captureStateLayout();
    private static final VarHandle LAST_ERROR = CAPTURE_LAYOUT.varHandle(MemoryLayout.PathElement.groupElement("GetLastError"));

    private WindowsSecurity() {
    }

    // --- Binding ---------------------------------------------------------------------------

    private static MethodHandle bind(SymbolLookup library, String name, FunctionDescriptor descriptor, Linker.Option... options) {
        var address = library.find(name).orElseThrow(() -> new UnsatisfiedLinkError("Windows export '" + name + "' not found."));
        return LINKER.downcallHandle(address, descriptor, options);
    }

    private static final class Kernel32 {
        static final SymbolLookup LIBRARY = SymbolLookup.libraryLookup("kernel32.dll", Arena.global());
        static final MethodHandle GET_SYSTEM_DIRECTORY = bind(LIBRARY, "GetSystemDirectoryW", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT));
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

    // --- File attributes -------------------------------------------------------------------

    /** GetFileAttributesW: the item's own attributes (a link is not followed), or {@link #INVALID_FILE_ATTRIBUTES}. */
    public static int fileAttributes(String path) {
        try (var arena = Arena.ofConfined()) {
            return (int) Kernel32.GET_FILE_ATTRIBUTES.invokeExact(arena.allocateFrom(path, UTF_16LE));
        } catch (Throwable t) {
            throw rethrow(t);
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
    public record Ace(int type, int flags, int mask, String sid) {
    }

    /**
     * An item's owner and DACL.
     *
     * @param ownerSid           the owner's SID string, or null if the descriptor has no owner
     * @param grantsEveryoneFull true when there is no DACL (or a NULL one), which grants everyone full access
     * @param aces               the DACL's entries, in order
     */
    public record SecurityDescriptorInfo(String ownerSid, boolean grantsEveryoneFull, List<Ace> aces) {
    }

    /**
     * The owner and DACL of a file or folder, by path, read without following a link.
     *
     * @throws AccessDeniedException this account may not read them
     * @throws IOException           they could not be read
     */
    public static SecurityDescriptorInfo securityDescriptorOf(String path) throws IOException {
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
     * The owner and DACL of the file or folder an open handle refers to, read through the handle.
     *
     * @param handle a CreateFileW handle opened with READ_CONTROL (GENERIC_READ includes it)
     * @throws IOException they could not be read
     */
    public static SecurityDescriptorInfo securityDescriptorOfHandle(MemorySegment handle) throws IOException {
        try (var arena = Arena.ofConfined()) {
            var descriptor = arena.allocate(ADDRESS);
            var error = (int) Advapi32.GET_SECURITY_INFO.invokeExact(handle, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                    MemorySegment.NULL, MemorySegment.NULL, MemorySegment.NULL, MemorySegment.NULL, descriptor);
            if (error != 0)
                throw new IOException("Could not read the opened file's security descriptor (error " + error + ").");

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
     * A security descriptor written in SDDL - for testing a policy against descriptors a real file
     * or folder would be hard to give.
     *
     * @throws IllegalArgumentException the SDDL is invalid
     */
    public static SecurityDescriptorInfo securityDescriptorFromSddl(String sddl) {
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

    // --- SIDs ------------------------------------------------------------------------------

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
    public static String canonicalSid(String sid) {
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
    public static String accountName(String sid) {
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
