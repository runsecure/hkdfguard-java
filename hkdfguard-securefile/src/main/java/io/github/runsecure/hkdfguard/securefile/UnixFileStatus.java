package io.github.runsecure.hkdfguard.securefile;

/**
 * What lstat reports about one path: who owns it, its permissions, and its type.
 *
 * @param ownerId the owning uid
 * @param groupId the owning gid
 * @param mode    the permission bits of {@code st_mode} (the low twelve bits: set-id, sticky, and
 *                read, write and execute for owner, group and others)
 * @param type    what kind of file it is - a symbolic link is reported as such, never followed
 */
record UnixFileStatus(long ownerId, long groupId, int mode, UnixFileType type) {
    /** S_IWGRP: writable by the file's group. */
    static final int GROUP_WRITE = 0020;

    /** S_IWOTH: writable by every other user. */
    static final int OTHER_WRITE = 0002;
}
