package io.github.runsecure.hkdfguard.platform.unix;

import java.util.Objects;

/**
 * A principal a file's access control list lets modify it, beyond what its permission bits say: a
 * POSIX ACL's named user or group with write permission (Linux), or a macOS ACL entry allowing any
 * right that changes the file or what a directory holds.
 *
 * @param kind whether {@code id} is a uid or a gid, or that the principal couldn't be identified
 * @param id   the uid or gid; -1 when {@code kind} is {@link Kind#UNKNOWN}
 */
public record UnixAclWriter(Kind kind, long id) {
    /** What an ACL entry names. */
    public enum Kind {
        /** A user, by uid. */
        USER,
        /** A group, by gid. */
        GROUP,
        /** A principal that maps to no uid or gid (a macOS entry whose GUID doesn't resolve). */
        UNKNOWN
    }

    /** @throws NullPointerException kind is null */
    public UnixAclWriter {
        Objects.requireNonNull(kind, "kind");
    }

    @Override
    public String toString() {
        return switch (kind) {
            case USER -> "uid " + id;
            case GROUP -> "group " + id;
            case UNKNOWN -> "a principal with no uid or gid";
        };
    }
}
