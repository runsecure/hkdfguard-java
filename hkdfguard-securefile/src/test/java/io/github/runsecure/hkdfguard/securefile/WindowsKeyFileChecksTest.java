package io.github.runsecure.hkdfguard.securefile;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.AccessDeniedException;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The Windows key-file location rules, checked against security descriptors written in SDDL and
 * against paths. TrustedKeyFileTest runs them against real files. Windows only: SIDs are read, and
 * SDDL parsed, by Windows itself.
 */
@EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
class WindowsKeyFileChecksTest {
    private static final String KEY_FILE = "C:\\HkdfGuardKeys\\myapp\\v1.key";

    private static final String SYSTEM = "S-1-5-18";
    private static final String ADMINISTRATORS = "S-1-5-32-544";
    private static final String TRUSTED_INSTALLER = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
    private static final String USERS = "S-1-5-32-545";
    private static final String AUTHENTICATED_USERS = "S-1-5-11";
    private static final String DEPLOYERS = "S-1-5-21-1111111111-2222222222-3333333333-1005";

    // FileSystemRights values.
    private static final int FULL_CONTROL = 0x1F01FF;
    private static final int MODIFY = 0x1301BF;
    private static final int WRITE = 0x116;
    private static final int READ_AND_EXECUTE_SYNCHRONIZE = 0x1200A9;

    private static List<String> trusted(String... extra) {
        return WindowsKeyFileChecks.trustedPrincipals(KeyFileTrust.ADMINISTRATORS_ONLY.withWindowsPrincipals(extra), WindowsNative::canonicalSid);
    }

    private static String allow(String who, int rights) {
        return String.format("(A;;0x%X;;;%s)", rights, who);
    }

    private static WindowsNative.SecurityDescriptorInfo security(String owner, String... aces) {
        return WindowsNative.securityDescriptorFromSddl("O:" + owner + "D:" + String.join("", aces));
    }

    private static String[] lockedAces(String... extra) {
        var aces = new String[4 + extra.length];
        aces[0] = allow(SYSTEM, FULL_CONTROL);
        aces[1] = allow(ADMINISTRATORS, FULL_CONTROL);
        aces[2] = allow(TRUSTED_INSTALLER, FULL_CONTROL);
        aces[3] = allow(USERS, READ_AND_EXECUTE_SYNCHRONIZE);
        System.arraycopy(extra, 0, aces, 4, extra.length);
        return aces;
    }

    private static WindowsNative.SecurityDescriptorInfo locked(String owner, String... extra) {
        return security(owner, lockedAces(extra));
    }

    private static void verify(WindowsNative.SecurityDescriptorInfo security, String item, int guardedRights, List<String> trusted)
            throws AccessDeniedException {
        WindowsKeyFileChecks.verifyTrustedOnly(security, KEY_FILE, item, guardedRights, trusted, WindowsNative::accountName);
    }

    @Test
    void trustedPrincipals_AlwaysIncludeSystemAdministratorsAndTrustedInstaller() {
        assertEquals(List.of(SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER), trusted());
    }

    @Test
    void trustedPrincipals_AddTheListedDeployers() {
        assertTrue(trusted(DEPLOYERS).contains(DEPLOYERS));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "S-1-1-0",      // Everyone
            "S-1-5-11",     // Authenticated Users
            "S-1-5-32-545", // Users
            "S-1-5-4",      // Interactive
            "S-1-5-7",      // Anonymous
    })
    void trustedPrincipals_RefuseGroupsEveryoneIsIn(String sid) {
        var ex = assertThrows(IllegalArgumentException.class, () -> trusted(sid));
        assertTrue(ex.getMessage().contains("every account"));
    }

    @Test
    void trustedPrincipals_RefuseSomethingThatIsNotASid() {
        var ex = assertThrows(IllegalArgumentException.class, () -> trusted("HkdfGuardDeployers"));
        assertTrue(ex.getMessage().contains("not a security identifier"));
    }

    @Test
    void verifyPathForm_LocalFixedDrive_Passes() {
        assertDoesNotThrow(() -> WindowsKeyFileChecks.verifyPathForm(KEY_FILE, DriveType.FIXED));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "\\\\server\\share\\v1.key",
            "\\\\?\\C:\\HkdfGuardKeys\\v1.key",
            "\\\\.\\PhysicalDrive0",
            "//server/share/v1.key",
    })
    void verifyPathForm_UncAndDevicePaths_AreRefused(String path) {
        var ex = assertThrows(AccessDeniedException.class, () -> WindowsKeyFileChecks.verifyPathForm(path, DriveType.FIXED));
        assertTrue(ex.getMessage().contains("UNC or device path"));
    }

    @ParameterizedTest
    @EnumSource(value = DriveType.class, names = "FIXED", mode = EnumSource.Mode.EXCLUDE)
    void verifyPathForm_OtherDrives_AreRefused(DriveType driveType) {
        var ex = assertThrows(AccessDeniedException.class, () -> WindowsKeyFileChecks.verifyPathForm(KEY_FILE, driveType));
        assertTrue(ex.getMessage().contains(driveType + " drive"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "\\\\?\\C:\\HkdfGuardKeys\\myapp\\v1.key",
            "\\\\?\\c:\\hkdfguardkeys\\MYAPP\\v1.KEY",
    })
    void verifyFinalPath_SamePath_Passes(String finalPath) {
        assertDoesNotThrow(() -> WindowsKeyFileChecks.verifyFinalPath(KEY_FILE, finalPath));
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "\\\\?\\D:\\elsewhere\\v1.key",                  // a junction or symbolic link on the path
            "\\\\?\\C:\\real\\HkdfGuardKeys\\myapp\\v1.key", // a substituted drive
            "\\\\?\\UNC\\server\\share\\myapp\\v1.key",      // a mapped network drive
            "C:\\HkdfGuardKeys\\myapp\\v1.key",              // not the form GetFinalPathNameByHandleW returns
    })
    void verifyFinalPath_ElsewhereOrRemote_IsRefused(String finalPath) {
        var ex = assertThrows(AccessDeniedException.class, () -> WindowsKeyFileChecks.verifyFinalPath(KEY_FILE, finalPath));
        assertTrue(ex.getMessage().contains(finalPath));
    }

    @Test
    void verifyFinalPath_ShortNameRequested_IsRefused() {
        assertThrows(AccessDeniedException.class, () ->
                WindowsKeyFileChecks.verifyFinalPath("C:\\PROGRA~1\\HkdfGuard\\v1.key", "\\\\?\\C:\\Program Files\\HkdfGuard\\v1.key"));
    }

    @Test
    void verifyNotReparsePoint_RealFolder_Passes() {
        // FILE_ATTRIBUTE_DIRECTORY
        assertDoesNotThrow(() -> WindowsKeyFileChecks.verifyNotReparsePoint(0x10, KEY_FILE, "C:\\HkdfGuardKeys"));
    }

    @Test
    void verifyNotReparsePoint_JunctionOrLink_IsRefused() {
        assertThrows(AccessDeniedException.class, () ->
                WindowsKeyFileChecks.verifyNotReparsePoint(0x10 | WindowsNative.FILE_ATTRIBUTE_REPARSE_POINT, KEY_FILE, "C:\\HkdfGuardKeys"));
    }

    @Test
    void verifyNotReparsePoint_AFolderThatCanNotBeExamined_IsRefused() {
        assertThrows(AccessDeniedException.class, () ->
                WindowsKeyFileChecks.verifyNotReparsePoint(WindowsNative.INVALID_FILE_ATTRIBUTES, KEY_FILE, "C:\\HkdfGuardKeys"));
    }

    @Test
    void verifyTrustedOnly_TrustedOwnerAndReadOnlyForEveryoneElse_Passes() {
        assertDoesNotThrow(() -> verify(locked(ADMINISTRATORS), KEY_FILE, WindowsKeyFileChecks.GUARDED_RIGHTS, trusted()));
    }

    @Test
    void verifyTrustedOnly_UntrustedOwner_IsRefused() {
        var ex = assertThrows(AccessDeniedException.class, () -> verify(locked(USERS), KEY_FILE, WindowsKeyFileChecks.GUARDED_RIGHTS, trusted()));
        assertTrue(ex.getMessage().contains("is owned by"));
    }

    @Test
    void verifyTrustedOnly_NoOwner_IsRefused() {
        var noOwner = WindowsNative.securityDescriptorFromSddl("D:" + allow(SYSTEM, FULL_CONTROL));

        var ex = assertThrows(AccessDeniedException.class, () -> verify(noOwner, KEY_FILE, WindowsKeyFileChecks.GUARDED_RIGHTS, trusted()));
        assertTrue(ex.getMessage().contains("an unknown principal"));
    }

    @Test
    void verifyTrustedOnly_NoDacl_IsRefused() {
        // A NULL DACL grants everyone everything.
        var noDacl = WindowsNative.securityDescriptorFromSddl("O:BAD:NO_ACCESS_CONTROL");

        var ex = assertThrows(AccessDeniedException.class, () -> verify(noDacl, KEY_FILE, WindowsKeyFileChecks.GUARDED_RIGHTS, trusted()));
        assertTrue(ex.getMessage().contains("no DACL"));
    }

    @ParameterizedTest
    @ValueSource(ints = {
            WindowsKeyFileChecks.WRITE_DATA,
            WindowsKeyFileChecks.APPEND_DATA,
            WindowsKeyFileChecks.WRITE_EXTENDED_ATTRIBUTES,
            WindowsKeyFileChecks.DELETE_SUBDIRECTORIES_AND_FILES,
            WindowsKeyFileChecks.DELETE,
            WindowsKeyFileChecks.CHANGE_PERMISSIONS,
            WindowsKeyFileChecks.TAKE_OWNERSHIP,
            MODIFY,
            FULL_CONTROL,
    })
    void verifyTrustedOnly_AnyWriteRightForAnUntrustedPrincipal_IsRefused(int rights) {
        var security = locked(ADMINISTRATORS, allow(USERS, rights));

        assertThrows(AccessDeniedException.class, () -> verify(security, KEY_FILE, WindowsKeyFileChecks.GUARDED_RIGHTS, trusted()));
    }

    @ParameterizedTest
    @ValueSource(strings = {"GA", "GW"}) // GENERIC_ALL, GENERIC_WRITE
    void verifyTrustedOnly_UnmappedGenericRights_AreRefused(String right) {
        // A real ACE can carry generic bits unmapped.
        var security = WindowsNative.securityDescriptorFromSddl("O:BAD:(A;;FA;;;SY)(A;;" + right + ";;;BU)");

        assertThrows(AccessDeniedException.class, () -> verify(security, KEY_FILE, WindowsKeyFileChecks.GUARDED_RIGHTS, trusted()));
    }

    @Test
    void verifyTrustedOnly_ATrustedDeployerMayOwnAndModify() {
        var security = locked(DEPLOYERS, allow(DEPLOYERS, MODIFY));

        assertDoesNotThrow(() -> verify(security, KEY_FILE, WindowsKeyFileChecks.GUARDED_RIGHTS, trusted(DEPLOYERS)));
        assertThrows(AccessDeniedException.class, () -> verify(security, KEY_FILE, WindowsKeyFileChecks.GUARDED_RIGHTS, trusted()));
    }

    @Test
    void verifyTrustedOnly_IgnoresDenyAndInheritOnlyEntries() {
        // A folder's: only a folder carries entries meant for what's created inside it.
        var security = security(ADMINISTRATORS, allow(ADMINISTRATORS, FULL_CONTROL), "(D;;FA;;;" + USERS + ")",
                String.format("(A;OICIIO;0x%X;;;%s)", MODIFY, AUTHENTICATED_USERS));

        assertDoesNotThrow(() -> verify(security, "C:\\HkdfGuardKeys", WindowsKeyFileChecks.GUARDED_RIGHTS, trusted()));
    }

    @Test
    void verifyTrustedOnly_AnEntryItCanNotEvaluate_IsRefused() {
        // An allow-object ACE (type 0x05): its trustee can't be read the plain way.
        var security = WindowsNative.securityDescriptorFromSddl(
                "O:BAD:(A;;FA;;;SY)(OA;;0x2;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)");

        var ex = assertThrows(AccessDeniedException.class, () -> verify(security, KEY_FILE, WindowsKeyFileChecks.GUARDED_RIGHTS, trusted()));
        assertTrue(ex.getMessage().contains("can't evaluate"));
    }

    @Test
    void verifyTrustedOnly_DriveRoot_AllowsCreatingFoldersButNotRenamingThem() {
        // A default C:\: Authenticated Users may create folders (AppendData) in the root itself.
        var root = locked(TRUSTED_INSTALLER, allow(AUTHENTICATED_USERS, WindowsKeyFileChecks.APPEND_DATA));
        assertDoesNotThrow(() -> verify(root, "C:\\", WindowsKeyFileChecks.GUARDED_ROOT_RIGHTS, trusted()));

        // The same entry on any folder below the root is refused: they could create files there.
        assertThrows(AccessDeniedException.class, () -> verify(root, "C:\\HkdfGuardKeys", WindowsKeyFileChecks.GUARDED_RIGHTS, trusted()));

        var renamable = locked(TRUSTED_INSTALLER, allow(AUTHENTICATED_USERS, WindowsKeyFileChecks.APPEND_DATA),
                allow(AUTHENTICATED_USERS, WindowsKeyFileChecks.DELETE_SUBDIRECTORIES_AND_FILES));
        assertThrows(AccessDeniedException.class, () -> verify(renamable, "C:\\", WindowsKeyFileChecks.GUARDED_ROOT_RIGHTS, trusted()));
    }

    @Test
    void verifyTrustedOnly_DescribesAnUnmappableSidByItsValue() {
        var security = locked(ADMINISTRATORS, allow(DEPLOYERS, WRITE));

        var ex = assertThrows(AccessDeniedException.class, () -> verify(security, KEY_FILE, WindowsKeyFileChecks.GUARDED_RIGHTS, trusted()));
        assertTrue(ex.getMessage().contains(DEPLOYERS));
        assertTrue(ex.getMessage().contains("grants 0x00000116 (WriteData, AppendData, WriteExtendedAttributes, WriteAttributes)"));
    }
}
