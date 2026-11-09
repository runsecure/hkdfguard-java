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
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * The system calls the Linux and macOS path checks need that Java doesn't expose as such: the
 * owner, group, permissions and type of a path itself, never what a symbolic link points to, and a
 * symbolic link's stored target. Linux uses statx and readlink from the C library this JVM already
 * runs on, found through the linker's default lookup - matched by name before anything is
 * searched, so LD_LIBRARY_PATH cannot substitute it - and statx (glibc 2.28 or later) has one struct
 * layout on every architecture. macOS uses lstat and readlink from libSystem, named by absolute
 * path, on arm64 only, whose struct stat this reads. Bound only on first use, so inert elsewhere.
 * <p>
 * A regular file's or directory's access control list is read too, for who it lets modify the path
 * beyond its permission bits ({@link UnixFileStatus#aclWriters()}). On Linux that is the POSIX ACL
 * (lgetxattr of system.posix_acl_access, never following a link): each named user or group whose
 * write permission survives the mask. The owner, owning group and others are already in the mode
 * bits - with a mask, the group bits are the mask, which bounds every named entry. NFSv4 ACLs
 * (system.nfs4_acl) aren't read. On macOS it is the extended ACL (acl_get_link_np): each allow entry
 * that applies to the path itself and grants any right that changes it - write or append data (add
 * a file or subdirectory), delete, delete a child, write attributes or extended attributes, change
 * the ACL or the owner - by the uid or gid its GUID maps to (mbr_uuid_to_id), or as
 * {@link UnixAclWriter.Kind#UNKNOWN} when it maps to neither. Deny entries are ignored: they can only
 * take rights away.
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

    // Linux: no such attribute, and a filesystem without attributes (ENOTSUP is EOPNOTSUPP there).
    private static final int LINUX_ENODATA = 61;
    private static final int LINUX_EOPNOTSUPP = 95;
    // macOS: ENOTSUP and EOPNOTSUPP differ.
    private static final int MAC_OS_ENOTSUP = 45;
    private static final int MAC_OS_EOPNOTSUPP = 102;

    // Linux POSIX ACL xattr: a u32 version (2), then 8-byte entries of u16 tag, u16 perm, u32 id, little-endian.
    private static final String POSIX_ACL_ACCESS = "system.posix_acl_access";
    private static final int POSIX_ACL_XATTR_VERSION = 2;
    private static final int ACL_USER = 0x02;
    private static final int ACL_GROUP = 0x08;
    private static final int ACL_MASK = 0x10;
    private static final int ACL_WRITE = 0x02;
    // Far beyond any ACL a filesystem stores (ext4 holds one in a 4 KiB block).
    private static final int ACL_BUFFER_SIZE = 64 * 1024;

    // macOS <sys/acl.h>.
    private static final int ACL_TYPE_EXTENDED = 0x00000100;
    private static final int ACL_FIRST_ENTRY = 0;
    private static final int ACL_NEXT_ENTRY = -1;
    private static final int ACL_EXTENDED_ALLOW = 1;
    private static final int ACL_ENTRY_ONLY_INHERIT = 1 << 8;
    private static final int[] ACL_MODIFYING_PERMISSIONS = {
            1 << 2,  // ACL_WRITE_DATA, ACL_ADD_FILE
            1 << 4,  // ACL_DELETE
            1 << 5,  // ACL_APPEND_DATA, ACL_ADD_SUBDIRECTORY
            1 << 6,  // ACL_DELETE_CHILD
            1 << 8,  // ACL_WRITE_ATTRIBUTES
            1 << 10, // ACL_WRITE_EXTATTRIBUTES
            1 << 12, // ACL_WRITE_SECURITY
            1 << 13, // ACL_CHANGE_OWNER
    };
    // <membership.h>
    private static final int ID_TYPE_UID = 0;
    private static final int ID_TYPE_GID = 1;

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
        static final MethodHandle LGETXATTR = bind(LIBRARY, "lgetxattr", FunctionDescriptor.of(JAVA_LONG, ADDRESS, ADDRESS, ADDRESS, JAVA_LONG));
    }

    private static final class MacOs {
        // By name: system libraries live in the dyld shared cache, not as files on disk.
        static final SymbolLookup LIBRARY = SymbolLookup.libraryLookup(MAC_OS_LIB_SYSTEM, Arena.global());
        static final MethodHandle LSTAT = bind(LIBRARY, "lstat", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle READLINK = bind(LIBRARY, "readlink", FunctionDescriptor.of(JAVA_LONG, ADDRESS, ADDRESS, JAVA_LONG));
    }

    // The macOS ACL calls, bound only when an ACL is read. Every one but acl_get_link_np reports
    // failure by its return value alone; errno is captured for that one.
    private static final class MacOsAcl {
        static final MethodHandle GET_LINK = bind(MacOs.LIBRARY, "acl_get_link_np", FunctionDescriptor.of(ADDRESS, ADDRESS, JAVA_INT));
        static final MethodHandle GET_ENTRY = plain("acl_get_entry", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT, ADDRESS));
        static final MethodHandle GET_TAG_TYPE = plain("acl_get_tag_type", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle GET_FLAGSET = plain("acl_get_flagset_np", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle GET_FLAG = plain("acl_get_flag_np", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT));
        static final MethodHandle GET_PERMSET = plain("acl_get_permset", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        static final MethodHandle GET_PERM = plain("acl_get_perm_np", FunctionDescriptor.of(JAVA_INT, ADDRESS, JAVA_INT));
        static final MethodHandle GET_QUALIFIER = plain("acl_get_qualifier", FunctionDescriptor.of(ADDRESS, ADDRESS));
        static final MethodHandle FREE = plain("acl_free", FunctionDescriptor.of(JAVA_INT, ADDRESS));
        static final MethodHandle UUID_TO_ID = plain("mbr_uuid_to_id", FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, ADDRESS));

        private static MethodHandle plain(String name, FunctionDescriptor descriptor) {
            return NativeCalls.bind(MacOs.LIBRARY, "C library", name, descriptor);
        }
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
            case 0 -> withAcl(path, status[0]);
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

    // A regular file's or directory's status with its ACL writers; any other kind as it is.
    private static UnixFileStatus withAcl(String path, UnixFileStatus status) throws IOException {
        if (status.type() != UnixFileType.REGULAR_FILE && status.type() != UnixFileType.DIRECTORY)
            return status;
        var writers = isLinux() ? linuxAclWriters(path) : macOsAclWriters(path);
        return writers.isEmpty() ? status : status.withAclWriters(writers);
    }

    private static List<UnixAclWriter> linuxAclWriters(String path) throws IOException {
        long length;
        int errno;
        byte[] acl;
        try (var arena = Arena.ofConfined()) {
            var capture = arena.allocate(CAPTURE_LAYOUT);
            var buffer = arena.allocate(ACL_BUFFER_SIZE);
            length = (long) Linux.LGETXATTR.invokeExact(capture, arena.allocateFrom(path), arena.allocateFrom(POSIX_ACL_ACCESS), buffer,
                    (long) ACL_BUFFER_SIZE);
            errno = length < 0 ? (int) ERRNO.get(capture, 0L) : 0;
            acl = length > 0 ? buffer.asSlice(0, length).toArray(JAVA_BYTE) : new byte[0];
        } catch (Throwable t) {
            throw rethrow(t);
        }

        if (length < 0) {
            if (errno == LINUX_ENODATA || errno == LINUX_EOPNOTSUPP)
                return List.of();
            if (errno == EACCES)
                throw new AccessDeniedException(path, null, "This account may not read the ACL of '" + path + "' (EACCES).");
            throw new IOException("Could not read the ACL of '" + path + "' (errno " + errno + ").");
        }
        return parseLinuxAcl(acl, path);
    }

    /**
     * The named users and groups a Linux system.posix_acl_access value lets write, after the mask.
     *
     * @throws IOException the value isn't a version 2 POSIX ACL
     */
    static List<UnixAclWriter> parseLinuxAcl(byte[] xattr, String path) throws IOException {
        if (xattr.length < 4 || (xattr.length - 4) % 8 != 0)
            throw new IOException("The ACL of '" + path + "' is " + xattr.length + " bytes, which isn't a POSIX ACL.");
        var data = ByteBuffer.wrap(xattr).order(ByteOrder.LITTLE_ENDIAN);
        if (data.getInt(0) != POSIX_ACL_XATTR_VERSION)
            throw new IOException("The ACL of '" + path + "' is version " + data.getInt(0) + ", not " + POSIX_ACL_XATTR_VERSION + ".");

        var mask = 0xFFFF;
        for (var at = 4; at < xattr.length; at += 8) {
            if (Short.toUnsignedInt(data.getShort(at)) == ACL_MASK)
                mask = Short.toUnsignedInt(data.getShort(at + 2));
        }

        var writers = new ArrayList<UnixAclWriter>();
        for (var at = 4; at < xattr.length; at += 8) {
            var tag = Short.toUnsignedInt(data.getShort(at));
            var permissions = Short.toUnsignedInt(data.getShort(at + 2)) & mask;
            if ((permissions & ACL_WRITE) == 0)
                continue;
            var id = Integer.toUnsignedLong(data.getInt(at + 4));
            if (tag == ACL_USER)
                writers.add(new UnixAclWriter(UnixAclWriter.Kind.USER, id));
            else if (tag == ACL_GROUP)
                writers.add(new UnixAclWriter(UnixAclWriter.Kind.GROUP, id));
        }
        return writers;
    }

    private static List<UnixAclWriter> macOsAclWriters(String path) throws IOException {
        requireAppleSilicon();
        try (var arena = Arena.ofConfined()) {
            var capture = arena.allocate(CAPTURE_LAYOUT);
            var acl = (MemorySegment) MacOsAcl.GET_LINK.invokeExact(capture, arena.allocateFrom(path), ACL_TYPE_EXTENDED);
            if (acl.equals(MemorySegment.NULL)) {
                var errno = (int) ERRNO.get(capture, 0L);
                if (errno == ENOENT || errno == MAC_OS_ENOTSUP || errno == MAC_OS_EOPNOTSUPP)
                    return List.of();
                if (errno == EACCES)
                    throw new AccessDeniedException(path, null, "This account may not read the ACL of '" + path + "' (EACCES).");
                throw new IOException("Could not read the ACL of '" + path + "' (errno " + errno + ").");
            }

            try {
                return macOsAllowedWriters(acl, arena);
            } finally {
                var ignored = (int) MacOsAcl.FREE.invokeExact(acl);
            }
        } catch (IOException e) {
            throw e;
        } catch (Throwable t) {
            throw rethrow(t);
        }
    }

    // Who the ACL's allow entries let modify the path itself.
    private static List<UnixAclWriter> macOsAllowedWriters(MemorySegment acl, Arena arena) throws Throwable {
        var writers = new ArrayList<UnixAclWriter>();
        var entry = arena.allocate(ADDRESS);
        var out = arena.allocate(ADDRESS);
        var tag = arena.allocate(JAVA_INT);
        for (var which = ACL_FIRST_ENTRY; (int) MacOsAcl.GET_ENTRY.invokeExact(acl, which, entry) == 0; which = ACL_NEXT_ENTRY) {
            var current = entry.get(ADDRESS, 0);
            if ((int) MacOsAcl.GET_TAG_TYPE.invokeExact(current, tag) != 0)
                throw new IOException("acl_get_tag_type failed.");
            if (tag.get(JAVA_INT, 0) != ACL_EXTENDED_ALLOW)
                continue;

            // An entry only inherited by what is created inside grants nothing on the path itself.
            if ((int) MacOsAcl.GET_FLAGSET.invokeExact(current, out) != 0)
                throw new IOException("acl_get_flagset_np failed.");
            if ((int) MacOsAcl.GET_FLAG.invokeExact(out.get(ADDRESS, 0), ACL_ENTRY_ONLY_INHERIT) == 1)
                continue;

            if ((int) MacOsAcl.GET_PERMSET.invokeExact(current, out) != 0)
                throw new IOException("acl_get_permset failed.");
            var permset = out.get(ADDRESS, 0);
            var modifies = false;
            for (var permission : ACL_MODIFYING_PERMISSIONS)
                modifies |= (int) MacOsAcl.GET_PERM.invokeExact(permset, permission) == 1;
            if (modifies)
                writers.add(macOsPrincipal(current, arena));
        }
        return writers;
    }

    // The uid or gid an entry's GUID maps to.
    private static UnixAclWriter macOsPrincipal(MemorySegment entry, Arena arena) throws Throwable {
        var qualifier = (MemorySegment) MacOsAcl.GET_QUALIFIER.invokeExact(entry);
        if (qualifier.equals(MemorySegment.NULL))
            return new UnixAclWriter(UnixAclWriter.Kind.UNKNOWN, -1);
        try {
            var id = arena.allocate(JAVA_INT);
            var idType = arena.allocate(JAVA_INT);
            if ((int) MacOsAcl.UUID_TO_ID.invokeExact(qualifier.reinterpret(16), id, idType) != 0)
                return new UnixAclWriter(UnixAclWriter.Kind.UNKNOWN, -1);
            var value = Integer.toUnsignedLong(id.get(JAVA_INT, 0));
            return switch (idType.get(JAVA_INT, 0)) {
                case ID_TYPE_UID -> new UnixAclWriter(UnixAclWriter.Kind.USER, value);
                case ID_TYPE_GID -> new UnixAclWriter(UnixAclWriter.Kind.GROUP, value);
                default -> new UnixAclWriter(UnixAclWriter.Kind.UNKNOWN, -1);
            };
        } finally {
            var ignored = (int) MacOsAcl.FREE.invokeExact(qualifier);
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
