package io.github.runsecure.hkdfguard.platform.windows;

import java.util.Collection;
import java.util.List;
import java.util.StringJoiner;
import java.util.function.Function;

/**
 * Which Windows access rights let a principal change what a path refers to, and the check that
 * finds the first entry in a security descriptor granting one to a principal outside a trusted set.
 * The trusted set, and how a violation is reported, are the caller's: the native library loader
 * trusts only SYSTEM, Administrators and TrustedInstaller, and the key-file checks also trust
 * the deployers an application names.
 */
public final class WindowsAccessRules {
    public static final String SYSTEM = "S-1-5-18";
    public static final String ADMINISTRATORS = "S-1-5-32-544";
    // NT SERVICE\TrustedInstaller has no well-known SID type; this is its fixed service SID.
    public static final String TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

    /** SYSTEM, Administrators and TrustedInstaller: trusted by every caller. */
    public static final List<String> ALWAYS_TRUSTED = List.of(SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER);

    // File access rights (winnt.h).
    public static final int WRITE_DATA = 0x0002;                // FILE_WRITE_DATA, FILE_ADD_FILE on a folder
    public static final int APPEND_DATA = 0x0004;               // FILE_APPEND_DATA, FILE_ADD_SUBDIRECTORY on a folder
    public static final int WRITE_EXTENDED_ATTRIBUTES = 0x0010; // FILE_WRITE_EA
    public static final int DELETE_SUBDIRECTORIES_AND_FILES = 0x0040; // FILE_DELETE_CHILD
    public static final int DELETE = 0x00010000;
    public static final int CHANGE_PERMISSIONS = 0x00040000;    // WRITE_DAC
    public static final int TAKE_OWNERSHIP = 0x00080000;        // WRITE_OWNER
    public static final int GENERIC_ALL = 0x10000000;
    public static final int GENERIC_WRITE = 0x40000000;

    /**
     * Any right that lets a principal change what a path refers to: write or append data (on a
     * folder, create files or folders), delete or rename (Delete on the item,
     * DeleteSubdirectoriesAndFiles on its parent), write extended attributes, or take over the ACL.
     * Generic bits are listed too, since an ACE can carry them unmapped.
     */
    public static final int GUARDED_RIGHTS = WRITE_DATA | APPEND_DATA | WRITE_EXTENDED_ATTRIBUTES | DELETE_SUBDIRECTORIES_AND_FILES
            | DELETE | CHANGE_PERMISSIONS | TAKE_OWNERSHIP | GENERIC_ALL | GENERIC_WRITE;

    /**
     * On a drive root, only what lets a principal rename or delete an entry directly beneath it -
     * delete-child, or taking over the ACL to grant it. Creating new entries there (Authenticated
     * Users may, on a default {@code C:\}) can't affect an existing path, and GENERIC_WRITE includes
     * none of these.
     */
    public static final int GUARDED_ROOT_RIGHTS = DELETE_SUBDIRECTORIES_AND_FILES | CHANGE_PERMISSIONS | TAKE_OWNERSHIP | GENERIC_ALL;

    // How describeRights names an access mask's bits: .NET's FileSystemRights names, then the generic bits.
    private static final String[] RIGHT_NAMES = {
            "ReadData", "WriteData", "AppendData", "ReadExtendedAttributes", "WriteExtendedAttributes", "ExecuteFile",
            "DeleteSubdirectoriesAndFiles", "ReadAttributes", "WriteAttributes", null, null, null, null, null, null, null,
            "Delete", "ReadPermissions", "ChangePermissions", "TakeOwnership", "Synchronize", null, null, null,
            "AccessSystemSecurity", "MaximumAllowed", null, null, "GenericAll", "GenericExecute", "GenericWrite", "GenericRead",
    };

    private WindowsAccessRules() {
    }

    /** Why a security descriptor lets someone untrusted change the item it describes. */
    public sealed interface Violation {
        /** @param sid the owner's SID string, or null if the descriptor has no owner */
        record UntrustedOwner(String sid) implements Violation {
        }

        /** There is no DACL, which grants every user full control. */
        record NoDacl() implements Violation {
        }

        /** An Allow entry grants a guarded right to an untrusted principal. */
        record UntrustedGrant(String sid, int mask) implements Violation {
        }

        /** An entry whose trustee can't be read the plain way, so what it grants can't be evaluated. */
        record UnevaluableAce(int type) implements Violation {
        }
    }

    /**
     * Requires a trusted owner, and no Allow entry granting any of {@code guardedRights} to anyone
     * else. Inherit-only entries don't apply to the item itself, and Deny entries can only remove
     * access, so both are ignored. A missing DACL grants everyone everything, and an entry whose
     * trustee can't be read the plain way can't be evaluated: both are violations.
     *
     * @param guardedRights {@link #GUARDED_RIGHTS} for a file or folder, {@link #GUARDED_ROOT_RIGHTS} for a drive root
     * @param trusted       the trusted principals, as canonical SID strings
     * @return the first violation, or null if there is none
     */
    public static Violation findViolation(WindowsSecurity.SecurityDescriptorInfo security, int guardedRights, Collection<String> trusted) {
        var owner = security.ownerSid();
        if (owner == null || !trusted.contains(owner))
            return new Violation.UntrustedOwner(owner);

        if (security.grantsEveryoneFull())
            return new Violation.NoDacl();

        for (var ace : security.aces()) {
            if ((ace.flags() & WindowsSecurity.INHERIT_ONLY_ACE) != 0)
                continue;

            switch (ace.type()) {
                case WindowsSecurity.ACCESS_DENIED_ACE_TYPE, WindowsSecurity.ACCESS_DENIED_OBJECT_ACE_TYPE,
                     WindowsSecurity.ACCESS_DENIED_CALLBACK_ACE_TYPE, WindowsSecurity.ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE -> {
                    // Can only remove access.
                }
                case WindowsSecurity.ACCESS_ALLOWED_ACE_TYPE, WindowsSecurity.ACCESS_ALLOWED_CALLBACK_ACE_TYPE -> {
                    if ((ace.mask() & guardedRights) != 0 && !trusted.contains(ace.sid()))
                        return new Violation.UntrustedGrant(ace.sid(), ace.mask());
                }
                // An allow-object ACE, or a type a DACL shouldn't hold: fail closed rather than guess.
                default -> {
                    return new Violation.UnevaluableAce(ace.type());
                }
            }
        }

        return null;
    }

    /**
     * A principal for a message: "DOMAIN\name (S-1-...)", the SID alone if it maps to no account,
     * or "an unknown principal" for none.
     *
     * @param accountName the account a SID string maps to, or null ({@link WindowsSecurity#accountName})
     */
    public static String describePrincipal(String sid, Function<String, String> accountName) {
        if (sid == null)
            return "an unknown principal";

        var name = accountName.apply(sid);
        return name == null ? sid : name + " (" + sid + ")";
    }

    /** An access mask as hex, then the names of its bits, such as "0x00120116 (WriteData, AppendData, ...)". */
    public static String describeRights(int mask) {
        var names = new StringJoiner(", ", " (", ")");
        for (var bit = 0; bit < RIGHT_NAMES.length; bit++) {
            if ((mask & (1 << bit)) != 0)
                names.add(RIGHT_NAMES[bit] != null ? RIGHT_NAMES[bit] : String.format("0x%08X", 1 << bit));
        }
        return String.format("0x%08X", mask) + (mask == 0 ? "" : names.toString());
    }
}
