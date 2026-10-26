package io.github.runsecure.hkdfguard.platform.unix;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.function.LongPredicate;
import java.util.function.Predicate;

/**
 * Resolves an absolute path the way the kernel would, from {@code /}, checking everything it
 * passes through: every directory and the final object must satisfy the caller's rule, and a
 * symbolic link is followed only if its owner is one the caller trusts - its target is then checked
 * in turn. What counts as trusted, and how a refusal is reported, are the caller's: the walk only
 * says where it stopped and why ({@link Resolution}).
 * <p>
 * The path is checked before it is opened, not through an opened descriptor. That is enough as
 * long as the caller's rule leaves nobody untrusted able to write to any directory on the resolved
 * path, or to the object: nobody untrusted can then change what it resolves to between the check
 * and the open.
 */
public final class UnixPathResolver {
    /** The kernel's own limit on symbolic links followed in one lookup. */
    public static final int MAX_SYMBOLIC_LINKS = 40;

    private UnixPathResolver() {
    }

    /** lstat-style status of a path: the path itself, never what a symbolic link points to. */
    @FunctionalInterface
    public interface StatusReader {
        /**
         * @return the status, or null if nothing is there
         * @throws IOException the path could not be examined
         */
        UnixFileStatus statusOrNull(String path) throws IOException;
    }

    /** A symbolic link's stored target. */
    @FunctionalInterface
    public interface LinkReader {
        /**
         * @return the target exactly as stored (possibly relative), or null if it can't be read as a link
         * @throws IOException the link could not be read
         */
        String readLink(String path) throws IOException;
    }

    /** Where a walk ended: resolved, or the first thing that stopped it. */
    public sealed interface Resolution {
        /** Every component passed; {@code path} contains no symbolic links. */
        record Resolved(String path, UnixFileType type) implements Resolution {
        }

        /** "/" itself could not be examined. */
        record RootUnreadable() implements Resolution {
        }

        /** Nothing is at {@code component}; everything above it passed. */
        record Missing(String component) implements Resolution {
        }

        /** The path continues through {@code component}, which is not a directory. */
        record NotADirectory(String component) implements Resolution {
        }

        /** {@code component} (or "/") is not a symbolic link, and fails the caller's rule. */
        record UntrustedComponent(String component, UnixFileStatus status) implements Resolution {
        }

        /** {@code component} is a symbolic link whose owner the caller doesn't trust. */
        record UntrustedLink(String component, UnixFileStatus status) implements Resolution {
        }

        /** More than {@link #MAX_SYMBOLIC_LINKS} symbolic links would be followed. */
        record TooManyLinks() implements Resolution {
        }

        /** {@code component} is a symbolic link whose target could not be read. */
        record UnreadableLink(String component) implements Resolution {
        }
    }

    /**
     * Resolves {@code path}, checking each component.
     *
     * @param path             an absolute path
     * @param getStatus        lstat-style status of a path
     * @param readLink         a symbolic link's stored target
     * @param trusted          whether a directory or the final object (never a link) may be on the path
     * @param trustedLinkOwner whether a symbolic link owned by this uid may be followed
     * @return where the walk ended
     * @throws IOException              a component could not be examined
     * @throws IllegalArgumentException the path is not absolute
     */
    public static Resolution resolve(String path, StatusReader getStatus, LinkReader readLink, Predicate<UnixFileStatus> trusted,
                                     LongPredicate trustedLinkOwner) throws IOException {
        if (!path.startsWith("/"))
            throw new IllegalArgumentException("'" + path + "' is not an absolute path.");

        var root = getStatus.statusOrNull("/");
        if (root == null)
            return new Resolution.RootUnreadable();
        if (!trusted.test(root))
            return new Resolution.UntrustedComponent("/", root);

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
                return new Resolution.NotADirectory(resolved);

            if (name.equals("..")) {
                // resolved never contains a symbolic link, so its parent is its lexical parent.
                resolved = parentOf(resolved);
                continue;
            }

            var candidate = resolved.equals("/") ? "/" + name : resolved + "/" + name;
            var status = getStatus.statusOrNull(candidate);
            if (status == null)
                return new Resolution.Missing(candidate);

            if (status.type() == UnixFileType.SYMBOLIC_LINK) {
                if (!trustedLinkOwner.test(status.ownerId()))
                    return new Resolution.UntrustedLink(candidate, status);
                if (++linksFollowed > MAX_SYMBOLIC_LINKS)
                    return new Resolution.TooManyLinks();

                var target = readLink.readLink(candidate);
                if (target == null)
                    return new Resolution.UnreadableLink(candidate);
                if (target.startsWith("/"))
                    resolved = "/";
                pushComponents(pending, target);
                continue;
            }

            if (!trusted.test(status))
                return new Resolution.UntrustedComponent(candidate, status);
            resolved = candidate;
            resolvedType = status.type();
        }

        return new Resolution.Resolved(resolved, resolvedType);
    }

    private static void pushComponents(Deque<String> pending, String path) {
        // -1: keep trailing empty components, as .NET's Split does; they are skipped like ".".
        var components = path.split("/", -1);
        for (var i = components.length - 1; i >= 0; i--)
            pending.push(components[i]);
    }

    /** The lexical parent of an absolute path with no symbolic links; "/" is its own parent. */
    public static String parentOf(String path) {
        var slash = path.lastIndexOf('/');
        return slash <= 0 ? "/" : path.substring(0, slash);
    }
}
