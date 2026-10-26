package io.github.runsecure.hkdfguard.securefile;

import io.github.runsecure.hkdfguard.platform.unix.UnixFileStatus;
import io.github.runsecure.hkdfguard.platform.unix.UnixFileType;
import io.github.runsecure.hkdfguard.platform.unix.UnixPathResolver;
import io.github.runsecure.hkdfguard.platform.unix.UnixPathResolver.Resolution;
import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.NoSuchFileException;

/**
 * Decides whether a key file's path on Linux or macOS can be trusted: resolves it the way the
 * kernel would, from {@code /}, checking everything it passes through. Every directory and the file
 * itself must be owned by root or a {@link KeyFileTrust#unixUserIds()} user, must not be writable
 * by others, and may be writable by its group only if that is a {@link KeyFileTrust#unixGroupIds()}
 * group. A symbolic link is followed only if a trusted user owns it, and its target is then checked
 * in turn - so macOS's root-owned /etc to private/etc works, and a link anyone else made doesn't.
 * Nothing under /tmp, /var/tmp or another world-writable directory passes, sticky or not.
 * <p>
 * The path is checked before it is opened, not through the opened descriptor. That is enough:
 * nobody untrusted can write to any directory on the resolved path, or to the file, so nobody
 * untrusted can change what it resolves to between the check and the open.
 */
final class UnixKeyFileChecks {
    private UnixKeyFileChecks() {
    }

    /**
     * Resolves {@code path} with {@link UnixPathResolver}, checking each component, and returns the
     * resolved path, which contains no symbolic links.
     *
     * @param path      an absolute path
     * @param trust     who besides root is trusted
     * @param getStatus lstat-style status of a path
     * @param readLink  a symbolic link's stored target
     * @return the resolved path
     * @throws NoSuchFileException      nothing is at the path, or a directory on it is missing
     * @throws AccessDeniedException    a component is not trusted, or the path isn't a regular file
     * @throws IOException              a component could not be examined
     * @throws IllegalArgumentException the path is not absolute
     */
    static String resolveTrusted(String path, KeyFileTrust trust, UnixPathResolver.StatusReader getStatus,
                                 UnixPathResolver.LinkReader readLink) throws IOException {
        var resolution = UnixPathResolver.resolve(path, getStatus, readLink, status -> whyUntrusted(status, trust) == null,
                uid -> isTrustedUser(uid, trust));

        return switch (resolution) {
            case Resolution.Resolved(var resolved, var type) -> {
                if (type != UnixFileType.REGULAR_FILE)
                    throw untrusted(path, "it resolves to '" + resolved + "', which is not a regular file");
                yield resolved;
            }
            case Resolution.RootUnreadable() -> throw new AccessDeniedException(path, null, "'/' could not be examined.");
            case Resolution.Missing(var component) ->
                    throw new NoSuchFileException(path, null, "Key file '" + path + "' was not found ('" + component + "' does not exist).");
            case Resolution.NotADirectory(var component) ->
                    throw new NoSuchFileException(path, null, "Key file '" + path + "' runs through '" + component + "', which is not a directory.");
            case Resolution.UntrustedComponent(var component, var status) ->
                    throw untrusted(path, "'" + component + "' " + whyUntrusted(status, trust));
            case Resolution.UntrustedLink(var component, var status) -> throw untrusted(path, "'" + component
                    + "' is a symbolic link owned by uid " + status.ownerId() + ", and only links owned by root or a trusted user are followed");
            case Resolution.TooManyLinks() -> throw untrusted(path, "it follows more than " + UnixPathResolver.MAX_SYMBOLIC_LINKS + " symbolic links");
            case Resolution.UnreadableLink(var component) -> throw untrusted(path, "'" + component + "' could not be read as a symbolic link");
        };
    }

    // Why a directory or the file may not be on a key file's path, or null if it may.
    private static String whyUntrusted(UnixFileStatus status, KeyFileTrust trust) {
        if (!isTrustedUser(status.ownerId(), trust))
            return "is owned by uid " + status.ownerId() + ", not root or a trusted user";

        if (status.otherWritable())
            return "is writable by every user";

        if (status.groupWritable() && !trust.unixGroupIds().contains(status.groupId()))
            return "is writable by group " + status.groupId() + ", which is not a trusted group";

        return null;
    }

    private static boolean isTrustedUser(long uid, KeyFileTrust trust) {
        return uid == 0 || trust.unixUserIds().contains(uid);
    }

    private static AccessDeniedException untrusted(String path, String why) {
        return new AccessDeniedException(path, null, "Key file '" + path + "' is not trusted: " + why
                + ". Keep key files where only root (or a trusted deployer, see KeyFileTrust) can write, all the way up from /.");
    }
}
