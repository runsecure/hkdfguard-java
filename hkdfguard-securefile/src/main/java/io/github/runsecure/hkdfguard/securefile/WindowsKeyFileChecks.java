package io.github.runsecure.hkdfguard.securefile;

import io.github.runsecure.hkdfguard.platform.windows.WindowsAccessRules;
import io.github.runsecure.hkdfguard.platform.windows.WindowsAccessRules.Violation;
import io.github.runsecure.hkdfguard.platform.windows.WindowsSecurity;
import java.nio.file.AccessDeniedException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

/**
 * Decides whether a key file on Windows can be trusted, by the native library's
 * ({@code hkdfguard_open_file}'s) rules:
 * <ul>
 * <li>The path names a file on a local fixed drive. UNC paths, device paths ({@code \\?\},
 * {@code \\.\}) and network drives are refused before anything is opened, so no server named in a
 * path is ever contacted.</li>
 * <li>The opened file's final path - with every symbolic link, junction, mount point and
 * substituted drive resolved - is the path that was asked for, once the full path has expanded any
 * 8.3 short name (it expands each one that exists on disk; a path still spelled with a short name
 * doesn't match the final path and is refused). So nothing on the path redirects it, and the
 * folders checked are the ones the file is in.</li>
 * <li>The file, and every folder above it, is owned by a trusted principal, and grants no one else
 * any right to write, append, delete, rename, change its permissions or take ownership. For a folder
 * that also covers creating files and folders in it. The drive root is held only to what could
 * rename or delete what's beneath it, since a default {@code C:\} lets Authenticated Users create
 * folders.</li>
 * </ul>
 * Trusted principals are SYSTEM, Administrators, TrustedInstaller and
 * {@link KeyFileTrust#windowsPrincipals()}.
 */
final class WindowsKeyFileChecks {
    // Groups every account, or every signed-in one, is in: trusting one trusts everybody. Everyone,
    // Authenticated Users, Users, Interactive, Anonymous.
    private static final Set<String> NEVER_TRUSTED = Set.of("S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4", "S-1-5-7");

    private WindowsKeyFileChecks() {
    }

    /**
     * The principals {@code trust} trusts, the always-trusted ones included, as canonical SID strings.
     *
     * @param canonicalSid a SID string's canonical form, or null if it isn't one ({@link WindowsSecurity#canonicalSid})
     * @throws IllegalArgumentException a listed SID isn't valid, or is one that every account is in
     */
    static List<String> trustedPrincipals(KeyFileTrust trust, Function<String, String> canonicalSid) {
        var trusted = new ArrayList<>(WindowsAccessRules.ALWAYS_TRUSTED);
        for (var value : trust.windowsPrincipals()) {
            var sid = value.isEmpty() ? null : canonicalSid.apply(value);
            if (sid == null)
                throw new IllegalArgumentException("KeyFileTrust.windowsPrincipals holds '" + value + "', which is not a security identifier (S-1-...).");

            if (NEVER_TRUSTED.contains(sid))
                throw new IllegalArgumentException("KeyFileTrust.windowsPrincipals holds " + WindowsAccessRules.describePrincipal(sid, WindowsSecurity::accountName)
                        + ", which every account (or every signed-in one) is in; trusting it would trust anyone to replace a key file.");
            trusted.add(sid);
        }

        return List.copyOf(trusted);
    }

    /**
     * Refuses a path that isn't on a local fixed drive, before anything is opened.
     *
     * @param fullPath  the absolute path ({@link WindowsNative#fullPath})
     * @param driveType the type of the drive the path's root names
     * @throws AccessDeniedException it isn't
     */
    static void verifyPathForm(String fullPath, DriveType driveType) throws AccessDeniedException {
        if (fullPath.startsWith("\\\\") || fullPath.startsWith("//"))
            throw untrusted(fullPath, "it is a UNC or device path; key files are only read from a local drive");

        if (driveType != DriveType.FIXED)
            throw untrusted(fullPath, "it is on a " + driveType + " drive; key files are only read from a local fixed drive");
    }

    /**
     * Requires the opened file's final path to be the one that was asked for.
     *
     * @param fullPath  the absolute path that was opened
     * @param finalPath GetFinalPathNameByHandleW's answer for the opened handle ({@code \\?\C:\...})
     * @throws AccessDeniedException they differ
     */
    static void verifyFinalPath(String fullPath, String finalPath) throws AccessDeniedException {
        final String localPrefix = "\\\\?\\";
        var opened = finalPath.startsWith(localPrefix) && !finalPath.regionMatches(true, 0, "\\\\?\\UNC\\", 0, 8)
                ? finalPath.substring(localPrefix.length())
                : null;

        if (opened == null || !opened.equalsIgnoreCase(fullPath))
            throw untrusted(fullPath, "it opens '" + finalPath
                    + "' - its path runs through a symbolic link, junction, mount point or substituted drive. Configure it as the full, real path");
    }

    /**
     * Refuses a folder that is a symbolic link, junction or other reparse point.
     *
     * @param attributes the folder's GetFileAttributesW value; {@link WindowsSecurity#INVALID_FILE_ATTRIBUTES}
     *                   has every bit set, so a folder that can't be examined is refused too
     * @throws AccessDeniedException it is one
     */
    static void verifyNotReparsePoint(int attributes, String fullPath, String folder) throws AccessDeniedException {
        if ((attributes & WindowsSecurity.FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            throw untrusted(fullPath, "'" + folder + "' is a symbolic link, junction or other reparse point");
    }

    /**
     * Requires a trusted owner, and no Allow entry granting any of {@code guardedRights}
     * ({@link WindowsAccessRules#GUARDED_RIGHTS} for the file and folders,
     * {@link WindowsAccessRules#GUARDED_ROOT_RIGHTS} for the drive root) to anyone else, by
     * {@link WindowsAccessRules#findViolation}'s rules.
     *
     * @param accountName the account a SID string maps to, or null - for describing principals
     * @throws AccessDeniedException the owner is untrusted, or an untrusted principal holds a guarded right
     */
    static void verifyTrustedOnly(WindowsSecurity.SecurityDescriptorInfo security, String fullPath, String item, int guardedRights,
                                  List<String> trusted, Function<String, String> accountName) throws AccessDeniedException {
        var violation = WindowsAccessRules.findViolation(security, guardedRights, trusted);
        if (violation == null)
            return;

        throw untrusted(fullPath, switch (violation) {
            case Violation.UntrustedOwner(var sid) -> "'" + item + "' is owned by " + WindowsAccessRules.describePrincipal(sid, accountName)
                    + ", not SYSTEM, Administrators, TrustedInstaller or a trusted deployer";
            case Violation.NoDacl() -> "'" + item + "' has no DACL, which grants every user full control";
            case Violation.UntrustedGrant(var sid, var mask) -> "'" + item + "' grants " + WindowsAccessRules.describeRights(mask) + " to "
                    + WindowsAccessRules.describePrincipal(sid, accountName);
            case Violation.UnevaluableAce(var type) -> String.format("'%s' has an access control entry of type 0x%02X, which this check can't evaluate",
                    item, type);
        });
    }

    private static AccessDeniedException untrusted(String path, String why) {
        return new AccessDeniedException(path, null, "Key file '" + path + "' is not trusted: " + why
                + ". Keep key files in a folder of their own that only administrators (or a trusted deployer, see KeyFileTrust) can modify, with inherited permissions removed.");
    }
}
