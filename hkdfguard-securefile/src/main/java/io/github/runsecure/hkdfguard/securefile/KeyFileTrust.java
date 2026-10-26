package io.github.runsecure.hkdfguard.securefile;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Who, besides the operating system's administrators, {@link TrustedKeyFile} trusts to have
 * written a key file it reads. A key file and every folder above it must be owned by a trusted
 * principal, and no one else may write, replace, rename or re-permission any of them: whoever can
 * replace a key file - and can also wrap under the KEK, as anyone allowed to encrypt with a
 * network KMS key can - chooses the DEK new data is encrypted under.
 * <p>
 * Always trusted: SYSTEM, Administrators and TrustedInstaller on Windows; root on Linux and
 * macOS. {@link #ADMINISTRATORS_ONLY} trusts no one else, which is the default. Add the account or
 * group your deployment writes key files as - never the account the application runs as, unless it
 * is a developer machine: an application that can rewrite its own key files can be made to roll
 * back to an older one.
 * <p>
 * Immutable: each {@code with...} method returns a copy with that list replaced.
 * <pre>{@code
 * var trust = KeyFileTrust.ADMINISTRATORS_ONLY
 *         .withWindowsPrincipals("S-1-5-21-1111111111-2222222222-3333333333-1005")
 *         .withUnixUserIds(1001)
 *         .withUnixGroupIds(2001);
 * }</pre>
 *
 * @param windowsPrincipals Windows security identifiers (SIDs, such as a deployers group's
 *                          "S-1-5-21-...-1005") that may also own, and hold write rights on, a key
 *                          file and the folders above it. Everyone, Authenticated Users, Users,
 *                          Interactive and Anonymous are refused when a key file is read.
 * @param unixUserIds       Linux and macOS user ids that may also own a key file, the directories
 *                          above it, and the symbolic links on its path
 * @param unixGroupIds      Linux and macOS group ids whose members may write a key file or a
 *                          directory above it: a group-writable file or directory is refused unless
 *                          its group is listed. Writable by others is refused whatever is listed.
 */
public record KeyFileTrust(List<String> windowsPrincipals, List<Long> unixUserIds, List<Long> unixGroupIds) {
    /** Trusts only the operating system's administrators. The default. */
    public static final KeyFileTrust ADMINISTRATORS_ONLY = new KeyFileTrust(List.of(), List.of(), List.of());

    // The largest uid or gid: both are unsigned 32-bit integers.
    private static final long MAX_ID = 0xFFFF_FFFFL;

    /**
     * Copies each list, so a list changed afterwards doesn't change what is trusted.
     *
     * @throws NullPointerException     a list, or an entry in one, is null
     * @throws IllegalArgumentException a uid or gid is outside 0 to 4294967295
     */
    public KeyFileTrust {
        windowsPrincipals = List.copyOf(Objects.requireNonNull(windowsPrincipals, "windowsPrincipals"));
        unixUserIds = requireIds(unixUserIds, "unixUserIds");
        unixGroupIds = requireIds(unixGroupIds, "unixGroupIds");
    }

    /**
     * A copy trusting these Windows SIDs instead of this instance's.
     *
     * @param sids security identifiers such as "S-1-5-21-...-1005"; checked when a key file is read
     * @return the copy
     */
    public KeyFileTrust withWindowsPrincipals(String... sids) {
        return new KeyFileTrust(List.of(sids), unixUserIds, unixGroupIds);
    }

    /**
     * A copy trusting these Linux and macOS user ids instead of this instance's.
     *
     * @param uids user ids, 0 to 4294967295
     * @return the copy
     */
    public KeyFileTrust withUnixUserIds(long... uids) {
        return new KeyFileTrust(windowsPrincipals, boxed(uids), unixGroupIds);
    }

    /**
     * A copy trusting these Linux and macOS group ids instead of this instance's.
     *
     * @param gids group ids, 0 to 4294967295
     * @return the copy
     */
    public KeyFileTrust withUnixGroupIds(long... gids) {
        return new KeyFileTrust(windowsPrincipals, unixUserIds, boxed(gids));
    }

    private static List<Long> boxed(long[] ids) {
        var list = new ArrayList<Long>(ids.length);
        for (var id : ids)
            list.add(id);
        return list;
    }

    private static List<Long> requireIds(List<Long> ids, String name) {
        var copy = List.copyOf(Objects.requireNonNull(ids, name));
        for (var id : copy) {
            if (id < 0 || id > MAX_ID)
                throw new IllegalArgumentException(name + " holds " + id + ", which is not a valid id (0 to " + MAX_ID + ").");
        }
        return copy;
    }
}
