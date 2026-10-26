package io.github.runsecure.hkdfguard.platform.unix;

/**
 * What lstat reports about one path: who owns it, its permissions, and its type.
 *
 * @param ownerId the owning uid
 * @param groupId the owning gid
 * @param mode    the permission bits of {@code st_mode} (the low twelve bits: set-id, sticky, and
 *                read, write and execute for owner, group and others)
 * @param type    what kind of file it is - a symbolic link is reported as such, never followed
 */
public record UnixFileStatus(long ownerId, long groupId, int mode, UnixFileType type) {
    /** S_IWGRP: writable by the file's group. */
    public static final int GROUP_WRITE = 0020;

    /** S_IWOTH: writable by every other user. */
    public static final int OTHER_WRITE = 0002;

    /** Whether the file's group may write it. */
    public boolean groupWritable() {
        return (mode & GROUP_WRITE) != 0;
    }

    /** Whether every other user may write it. */
    public boolean otherWritable() {
        return (mode & OTHER_WRITE) != 0;
    }
}
