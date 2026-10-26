package io.github.runsecure.hkdfguard.platform.windows;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import io.github.runsecure.hkdfguard.platform.windows.WindowsAccessRules.Violation;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Which entry of a security descriptor the shared rule reports, and how rights and principals are
 * described. The loader's and the key-file checks' tests hold the rule to their own trusted sets
 * and messages. Descriptors are written in SDDL, which only Windows parses.
 */
class WindowsAccessRulesTest {
    private static final String USERS = "S-1-5-32-545";
    private static final String DEPLOYERS = "S-1-5-21-1111111111-2222222222-3333333333-1005";

    private static final List<String> TRUSTED = WindowsAccessRules.ALWAYS_TRUSTED;

    private static WindowsSecurity.SecurityDescriptorInfo sddl(String sddl) {
        return WindowsSecurity.securityDescriptorFromSddl(sddl);
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "SDDL is parsed by Windows.")
    void aTrustedOwner_AndWriteRightsForTrustedPrincipalsOnly_IsNoViolation() {
        var security = sddl("O:BAD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200A9;;;BU)");

        assertNull(WindowsAccessRules.findViolation(security, WindowsAccessRules.GUARDED_RIGHTS, TRUSTED));
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "SDDL is parsed by Windows.")
    void anUntrustedOwner_OrNone_IsTheFirstViolation() {
        assertEquals(new Violation.UntrustedOwner(USERS),
                WindowsAccessRules.findViolation(sddl("O:BUD:(A;;FA;;;BU)"), WindowsAccessRules.GUARDED_RIGHTS, TRUSTED));
        assertEquals(new Violation.UntrustedOwner(null),
                WindowsAccessRules.findViolation(sddl("D:(A;;FA;;;SY)"), WindowsAccessRules.GUARDED_RIGHTS, TRUSTED));
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "SDDL is parsed by Windows.")
    void noDacl_IsAViolation() {
        assertEquals(new Violation.NoDacl(), WindowsAccessRules.findViolation(sddl("O:BAD:NO_ACCESS_CONTROL"), WindowsAccessRules.GUARDED_RIGHTS, TRUSTED));
    }

    @ParameterizedTest
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "SDDL is parsed by Windows.")
    @ValueSource(ints = {
            WindowsAccessRules.WRITE_DATA,
            WindowsAccessRules.APPEND_DATA,
            WindowsAccessRules.WRITE_EXTENDED_ATTRIBUTES,
            WindowsAccessRules.DELETE_SUBDIRECTORIES_AND_FILES,
            WindowsAccessRules.DELETE,
            WindowsAccessRules.CHANGE_PERMISSIONS,
            WindowsAccessRules.TAKE_OWNERSHIP,
            WindowsAccessRules.GENERIC_ALL,
            WindowsAccessRules.GENERIC_WRITE,
    })
    void anyGuardedRightForAnUntrustedPrincipal_IsAViolation(int right) {
        var security = sddl(String.format("O:BAD:(A;;FA;;;SY)(A;;0x%X;;;BU)", right));

        var violation = WindowsAccessRules.findViolation(security, WindowsAccessRules.GUARDED_RIGHTS, TRUSTED);

        assertEquals(new Violation.UntrustedGrant(USERS, right), violation);
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "SDDL is parsed by Windows.")
    void aPrincipalTheCallerTrusts_MayHoldGuardedRights() {
        var security = sddl("O:" + DEPLOYERS + "D:(A;;FA;;;SY)(A;;FA;;;" + DEPLOYERS + ")");

        assertEquals(new Violation.UntrustedOwner(DEPLOYERS), WindowsAccessRules.findViolation(security, WindowsAccessRules.GUARDED_RIGHTS, TRUSTED));
        assertNull(WindowsAccessRules.findViolation(security, WindowsAccessRules.GUARDED_RIGHTS, List.of("S-1-5-18", DEPLOYERS)));
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "SDDL is parsed by Windows.")
    void inheritOnlyAndDenyEntries_AreIgnored() {
        // Inherit-only: applies to children only. Deny: can only remove access.
        var security = sddl("O:BAD:(A;;FA;;;SY)(A;OICIIO;FA;;;BU)(D;;FA;;;BU)");

        assertNull(WindowsAccessRules.findViolation(security, WindowsAccessRules.GUARDED_RIGHTS, TRUSTED));
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "SDDL is parsed by Windows.")
    void anAllowObjectEntry_CantBeEvaluated() {
        var security = sddl("O:BAD:(A;;FA;;;SY)(OA;;FA;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)");

        assertEquals(new Violation.UnevaluableAce(0x05), WindowsAccessRules.findViolation(security, WindowsAccessRules.GUARDED_RIGHTS, TRUSTED));
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "SDDL is parsed by Windows.")
    void theDriveRootsRights_IgnoreCreatingEntries_ButNotRenamingThem() {
        var creatable = sddl(String.format("O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:(A;;FA;;;SY)(A;;0x%X;;;AU)",
                WindowsAccessRules.APPEND_DATA | WindowsAccessRules.WRITE_DATA | WindowsAccessRules.GENERIC_WRITE));
        var renamable = sddl(String.format("O:BAD:(A;;FA;;;SY)(A;;0x%X;;;AU)", WindowsAccessRules.DELETE_SUBDIRECTORIES_AND_FILES));

        assertNull(WindowsAccessRules.findViolation(creatable, WindowsAccessRules.GUARDED_ROOT_RIGHTS, TRUSTED));
        assertEquals(new Violation.UntrustedGrant("S-1-5-11", WindowsAccessRules.DELETE_SUBDIRECTORIES_AND_FILES),
                WindowsAccessRules.findViolation(renamable, WindowsAccessRules.GUARDED_ROOT_RIGHTS, TRUSTED));
    }

    @Test
    void describeRights_NamesEachBit() {
        assertEquals("0x00000000", WindowsAccessRules.describeRights(0));
        assertEquals("0x00000006 (WriteData, AppendData)", WindowsAccessRules.describeRights(0x6));
        assertEquals("0x50000000 (GenericAll, GenericWrite)", WindowsAccessRules.describeRights(0x50000000));
        assertEquals("0x00000200 (0x00000200)", WindowsAccessRules.describeRights(0x200));
    }

    @Test
    void describePrincipal_UsesTheAccountNameWhenThereIsOne() {
        assertEquals("BUILTIN\\Users (S-1-5-32-545)", WindowsAccessRules.describePrincipal(USERS, sid -> "BUILTIN\\Users"));
        assertEquals(DEPLOYERS, WindowsAccessRules.describePrincipal(DEPLOYERS, sid -> null));
        assertEquals("an unknown principal", WindowsAccessRules.describePrincipal(null, sid -> "never asked"));
    }
}
