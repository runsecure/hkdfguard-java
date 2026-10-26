package io.github.runsecure.hkdfguard.securefile;

import java.nio.file.AccessDeniedException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.StringJoiner;
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
    static final String SYSTEM = "S-1-5-18";
    static final String ADMINISTRATORS = "S-1-5-32-544";
    // NT SERVICE\TrustedInstaller has no well-known SID type; this is its fixed service SID.
    static final String TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    private static final List<String> ALWAYS_TRUSTED = List.of(SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER);

    // Groups every account, or every signed-in one, is in: trusting one trusts everybody. Everyone,
    // Authenticated Users, Users, Interactive, Anonymous.
    private static final Set<String> NEVER_TRUSTED = Set.of("S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-4", "S-1-5-7");

    // File access rights (winnt.h).
    static final int WRITE_DATA = 0x0002;                // FILE_WRITE_DATA, FILE_ADD_FILE on a folder
    static final int APPEND_DATA = 0x0004;               // FILE_APPEND_DATA, FILE_ADD_SUBDIRECTORY on a folder
    static final int WRITE_EXTENDED_ATTRIBUTES = 0x0010; // FILE_WRITE_EA
    static final int DELETE_SUBDIRECTORIES_AND_FILES = 0x0040; // FILE_DELETE_CHILD
    static final int DELETE = 0x00010000;
    static final int CHANGE_PERMISSIONS = 0x00040000;    // WRITE_DAC
    static final int TAKE_OWNERSHIP = 0x00080000;        // WRITE_OWNER
    static final int GENERIC_ALL = 0x10000000;
    static final int GENERIC_WRITE = 0x40000000;

    // Any right that lets a principal change what this path reads: write or append data (on a
    // folder, create files or folders), delete or rename (Delete on the item,
    // DeleteSubdirectoriesAndFiles on its parent), write extended attributes, or take over the
    // ACL. Generic bits are listed too, since an ACE can carry them unmapped.
    static final int GUARDED_RIGHTS = WRITE_DATA | APPEND_DATA | WRITE_EXTENDED_ATTRIBUTES | DELETE_SUBDIRECTORIES_AND_FILES
            | DELETE | CHANGE_PERMISSIONS | TAKE_OWNERSHIP | GENERIC_ALL | GENERIC_WRITE;

    // On the drive root, only what lets a principal rename or delete an entry directly beneath it.
    static final int GUARDED_ROOT_RIGHTS = DELETE_SUBDIRECTORIES_AND_FILES | CHANGE_PERMISSIONS | TAKE_OWNERSHIP | GENERIC_ALL;

    // How describeRights names an access mask's bits: .NET's FileSystemRights names, then the generic bits.
    private static final String[] RIGHT_NAMES = {
            "ReadData", "WriteData", "AppendData", "ReadExtendedAttributes", "WriteExtendedAttributes", "ExecuteFile",
            "DeleteSubdirectoriesAndFiles", "ReadAttributes", "WriteAttributes", null, null, null, null, null, null, null,
            "Delete", "ReadPermissions", "ChangePermissions", "TakeOwnership", "Synchronize", null, null, null,
            "AccessSystemSecurity", "MaximumAllowed", null, null, "GenericAll", "GenericExecute", "GenericWrite", "GenericRead",
    };

    private WindowsKeyFileChecks() {
    }

    /**
     * The principals {@code trust} trusts, the always-trusted ones included, as canonical SID strings.
     *
     * @param canonicalSid a SID string's canonical form, or null if it isn't one ({@link WindowsNative#canonicalSid})
     * @throws IllegalArgumentException a listed SID isn't valid, or is one that every account is in
     */
    static List<String> trustedPrincipals(KeyFileTrust trust, Function<String, String> canonicalSid) {
        var trusted = new ArrayList<>(ALWAYS_TRUSTED);
        for (var value : trust.windowsPrincipals()) {
            var sid = value.isEmpty() ? null : canonicalSid.apply(value);
            if (sid == null)
                throw new IllegalArgumentException("KeyFileTrust.windowsPrincipals holds '" + value + "', which is not a security identifier (S-1-...).");

            if (NEVER_TRUSTED.contains(sid))
                throw new IllegalArgumentException("KeyFileTrust.windowsPrincipals holds " + describe(sid, WindowsNative::accountName)
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
     * @param attributes the folder's GetFileAttributesW value; {@link WindowsNative#INVALID_FILE_ATTRIBUTES}
     *                   has every bit set, so a folder that can't be examined is refused too
     * @throws AccessDeniedException it is one
     */
    static void verifyNotReparsePoint(int attributes, String fullPath, String folder) throws AccessDeniedException {
        if ((attributes & WindowsNative.FILE_ATTRIBUTE_REPARSE_POINT) != 0)
            throw untrusted(fullPath, "'" + folder + "' is a symbolic link, junction or other reparse point");
    }

    /**
     * Requires a trusted owner, and no Allow entry granting any of {@code guardedRights}
     * ({@link #GUARDED_RIGHTS} for the file and folders, {@link #GUARDED_ROOT_RIGHTS} for the drive
     * root) to anyone else. Inherit-only entries don't apply to the item itself, and Deny entries can
     * only remove access, so both are ignored. A missing DACL grants everyone everything, and an
     * entry whose trustee can't be read the plain way can't be evaluated: both are refused.
     *
     * @param accountName the account a SID string maps to, or null - for describing principals
     * @throws AccessDeniedException the owner is untrusted, or an untrusted principal holds a guarded right
     */
    static void verifyTrustedOnly(WindowsNative.SecurityDescriptorInfo security, String fullPath, String item, int guardedRights,
                                  List<String> trusted, Function<String, String> accountName) throws AccessDeniedException {
        var owner = security.ownerSid();
        if (owner == null || !trusted.contains(owner))
            throw untrusted(fullPath, "'" + item + "' is owned by " + describe(owner, accountName)
                    + ", not SYSTEM, Administrators, TrustedInstaller or a trusted deployer");

        if (security.grantsEveryoneFull())
            throw untrusted(fullPath, "'" + item + "' has no DACL, which grants every user full control");

        for (var ace : security.aces()) {
            if ((ace.flags() & WindowsNative.INHERIT_ONLY_ACE) != 0)
                continue;

            switch (ace.type()) {
                case WindowsNative.ACCESS_DENIED_ACE_TYPE, WindowsNative.ACCESS_DENIED_OBJECT_ACE_TYPE,
                     WindowsNative.ACCESS_DENIED_CALLBACK_ACE_TYPE, WindowsNative.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE -> {
                    // Can only remove access.
                }
                case WindowsNative.ACCESS_ALLOWED_ACE_TYPE, WindowsNative.ACCESS_ALLOWED_CALLBACK_ACE_TYPE -> {
                    if ((ace.mask() & guardedRights) != 0 && !trusted.contains(ace.sid()))
                        throw untrusted(fullPath, "'" + item + "' grants " + describeRights(ace.mask()) + " to " + describe(ace.sid(), accountName));
                }
                default -> throw untrusted(fullPath, String.format(
                        "'%s' has an access control entry of type 0x%02X, which this check can't evaluate", item, ace.type()));
            }
        }
    }

    private static AccessDeniedException untrusted(String path, String why) {
        return new AccessDeniedException(path, null, "Key file '" + path + "' is not trusted: " + why
                + ". Keep key files in a folder of their own that only administrators (or a trusted deployer, see KeyFileTrust) can modify, with inherited permissions removed.");
    }

    private static String describe(String sid, Function<String, String> accountName) {
        if (sid == null)
            return "an unknown principal";

        var name = accountName.apply(sid);
        return name == null ? sid : name + " (" + sid + ")";
    }

    /** An access mask as hex, then the names of its bits, such as "0x00120116 (WriteData, AppendData, ...)". */
    static String describeRights(int mask) {
        var names = new StringJoiner(", ", " (", ")");
        for (var bit = 0; bit < RIGHT_NAMES.length; bit++) {
            if ((mask & (1 << bit)) != 0)
                names.add(RIGHT_NAMES[bit] != null ? RIGHT_NAMES[bit] : String.format("0x%08X", 1 << bit));
        }
        return String.format("0x%08X", mask) + (mask == 0 ? "" : names.toString());
    }
}
