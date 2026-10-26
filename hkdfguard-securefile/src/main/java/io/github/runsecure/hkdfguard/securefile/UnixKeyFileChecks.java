package io.github.runsecure.hkdfguard.securefile;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.NoSuchFileException;
import java.util.ArrayDeque;
import java.util.Deque;

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
    /** The kernel's own limit on symbolic links followed in one lookup. */
    static final int MAX_SYMBOLIC_LINKS = 40;

    private UnixKeyFileChecks() {
    }

    /** lstat-style status of a path: the path itself, never what a symbolic link points to. */
    @FunctionalInterface
    interface StatusReader {
        /**
         * @return the status, or null if nothing is there
         * @throws IOException the path could not be examined
         */
        UnixFileStatus statusOrNull(String path) throws IOException;
    }

    /** A symbolic link's stored target. */
    @FunctionalInterface
    interface LinkReader {
        /**
         * @return the target exactly as stored (possibly relative), or null if it can't be read as a link
         * @throws IOException the link could not be read
         */
        String readLink(String path) throws IOException;
    }

    /**
     * Resolves {@code path}, checking each component, and returns the resolved path, which contains
     * no symbolic links.
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
    static String resolveTrusted(String path, KeyFileTrust trust, StatusReader getStatus, LinkReader readLink) throws IOException {
        if (!path.startsWith("/"))
            throw new IllegalArgumentException("'" + path + "' is not an absolute path.");

        var root = getStatus.statusOrNull("/");
        if (root == null)
            throw new AccessDeniedException(path, null, "'/' could not be examined.");
        requireTrusted("/", root, trust, path);

        Deque<String> pending = new ArrayDeque<>();
        pushComponents(pending, path);
        var resolved = "/";
        var resolvedType = UnixFileType.DIRECTORY;
        var linksFollowed = 0;

        while (!pending.isEmpty()) {
            var name = pending.pop();
            if (name.isEmpty() || name.equals("."))
                continue;

            if (resolvedType != UnixFileType.DIRECTORY)
                throw new NoSuchFileException(path, null, "Key file '" + path + "' runs through '" + resolved + "', which is not a directory.");

            if (name.equals("..")) {
                // resolved never contains a symbolic link, so its parent is its lexical parent.
                resolved = parentOf(resolved);
                continue;
            }

            var candidate = resolved.equals("/") ? "/" + name : resolved + "/" + name;
            var status = getStatus.statusOrNull(candidate);
            if (status == null)
                throw new NoSuchFileException(path, null, "Key file '" + path + "' was not found ('" + candidate + "' does not exist).");

            if (status.type() == UnixFileType.SYMBOLIC_LINK) {
                if (!isTrustedUser(status.ownerId(), trust))
                    throw untrusted(path, "'" + candidate + "' is a symbolic link owned by uid " + status.ownerId()
                            + ", and only links owned by root or a trusted user are followed");
                if (++linksFollowed > MAX_SYMBOLIC_LINKS)
                    throw untrusted(path, "it follows more than " + MAX_SYMBOLIC_LINKS + " symbolic links");

                var target = readLink.readLink(candidate);
                if (target == null)
                    throw untrusted(path, "'" + candidate + "' could not be read as a symbolic link");
                if (target.startsWith("/"))
                    resolved = "/";
                pushComponents(pending, target);
                continue;
            }

            requireTrusted(candidate, status, trust, path);
            resolved = candidate;
            resolvedType = status.type();
        }

        if (resolvedType != UnixFileType.REGULAR_FILE)
            throw untrusted(path, "it resolves to '" + resolved + "', which is not a regular file");

        return resolved;
    }

    private static void requireTrusted(String candidate, UnixFileStatus status, KeyFileTrust trust, String path) throws AccessDeniedException {
        if (!isTrustedUser(status.ownerId(), trust))
            throw untrusted(path, "'" + candidate + "' is owned by uid " + status.ownerId() + ", not root or a trusted user");

        if ((status.mode() & UnixFileStatus.OTHER_WRITE) != 0)
            throw untrusted(path, "'" + candidate + "' is writable by every user");

        if ((status.mode() & UnixFileStatus.GROUP_WRITE) != 0 && !trust.unixGroupIds().contains(status.groupId()))
            throw untrusted(path, "'" + candidate + "' is writable by group " + status.groupId() + ", which is not a trusted group");
    }

    private static boolean isTrustedUser(long uid, KeyFileTrust trust) {
        return uid == 0 || trust.unixUserIds().contains(uid);
    }

    private static AccessDeniedException untrusted(String path, String why) {
        return new AccessDeniedException(path, null, "Key file '" + path + "' is not trusted: " + why
                + ". Keep key files where only root (or a trusted deployer, see KeyFileTrust) can write, all the way up from /.");
    }

    private static void pushComponents(Deque<String> pending, String path) {
        // -1: keep trailing empty components, as .NET's Split does; they are skipped like ".".
        var components = path.split("/", -1);
        for (var i = components.length - 1; i >= 0; i--)
            pending.push(components[i]);
    }

    /** The lexical parent of an absolute path with no symbolic links; "/" is its own parent. */
    static String parentOf(String path) {
        var slash = path.lastIndexOf('/');
        return slash <= 0 ? "/" : path.substring(0, slash);
    }
}
