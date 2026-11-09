package io.github.runsecure.hkdfguard.platform.unix;

import java.util.List;

/**
 * What lstat reports about one path: who owns it, its permissions, and its type - and who else its
 * access control list lets modify it.
 *
 * @param ownerId    the owning uid
 * @param groupId    the owning gid
 * @param mode       the permission bits of {@code st_mode} (the low twelve bits: set-id, sticky, and
 *                   read, write and execute for owner, group and others)
 * @param type       what kind of file it is - a symbolic link is reported as such, never followed
 * @param aclWriters the principals its ACL lets modify it beyond its permission bits; empty when it
 *                   has no ACL, or one that grants nothing more. Copied.
 */
public record UnixFileStatus(long ownerId, long groupId, int mode, UnixFileType type, List<UnixAclWriter> aclWriters) {
    /** S_IWGRP: writable by the file's group. */
    public static final int GROUP_WRITE = 0_020; // octal

    /** S_IWOTH: writable by every other user. */
    public static final int OTHER_WRITE = 0_002; // octal

    /** @throws NullPointerException aclWriters is null, or holds a null */
    public UnixFileStatus {
        aclWriters = List.copyOf(aclWriters);
    }

    /** A status with no ACL writers. */
    public UnixFileStatus(long ownerId, long groupId, int mode, UnixFileType type) {
        this(ownerId, groupId, mode, type, List.of());
    }

    /** The same status, with these ACL writers. */
    public UnixFileStatus withAclWriters(List<UnixAclWriter> writers) {
        return new UnixFileStatus(ownerId, groupId, mode, type, writers);
    }

    /** Whether the file's group may write it. */
    public boolean groupWritable() {
        return (mode & GROUP_WRITE) != 0;
    }

    /** Whether every other user may write it. */
    public boolean otherWritable() {
        return (mode & OTHER_WRITE) != 0;
    }
}
