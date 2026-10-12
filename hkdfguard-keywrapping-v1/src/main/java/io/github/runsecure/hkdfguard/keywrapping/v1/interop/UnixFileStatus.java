package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import java.nio.file.attribute.PosixFilePermission;
import java.util.EnumSet;
import java.util.Set;

/**
 * What lstat reports about one path: who owns it, its permissions, and its type.
 *
 * @param ownerId     the owning uid
 * @param groupId     the owning gid
 * @param permissions the permission bits
 * @param type        what kind of file it is - a symbolic link is reported as such, never followed
 */
record UnixFileStatus(long ownerId, long groupId, Set<PosixFilePermission> permissions, UnixFileType type) {
    UnixFileStatus {
        permissions = permissions.isEmpty() ? Set.of() : Set.copyOf(EnumSet.copyOf(permissions));
    }

    /** The permission bits of a {@code st_mode}. */
    static Set<PosixFilePermission> permissionsFromMode(int mode) {
        var permissions = EnumSet.noneOf(PosixFilePermission.class);
        PosixFilePermission[] order = {
                PosixFilePermission.OTHERS_EXECUTE, PosixFilePermission.OTHERS_WRITE, PosixFilePermission.OTHERS_READ,
                PosixFilePermission.GROUP_EXECUTE, PosixFilePermission.GROUP_WRITE, PosixFilePermission.GROUP_READ,
                PosixFilePermission.OWNER_EXECUTE, PosixFilePermission.OWNER_WRITE, PosixFilePermission.OWNER_READ,
        };
        for (var bit = 0; bit < order.length; bit++)
            if ((mode & (1 << bit)) != 0)
                permissions.add(order[bit]);
        return permissions;
    }
}
