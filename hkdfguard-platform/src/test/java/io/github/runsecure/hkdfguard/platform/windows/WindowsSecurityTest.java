package io.github.runsecure.hkdfguard.platform.windows;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;

/** The Win32 security-descriptor, SID and attribute calls, against Windows itself. */
@EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
class WindowsSecurityTest {
    private static final int FILE_ATTRIBUTE_DIRECTORY = 0x10;

    private static String systemDirectory() {
        return Path.of(System.getenv("SystemRoot"), "System32").toString();
    }

    @Test
    void anSddlDescriptor_IsReadBackEntryByEntry() {
        var security = WindowsSecurity.securityDescriptorFromSddl("O:BAD:(A;;FA;;;SY)(D;OICI;0x116;;;BU)(A;IO;0x1200A9;;;S-1-5-11)");

        assertEquals("S-1-5-32-544", security.ownerSid());
        assertFalse(security.grantsEveryoneFull());
        assertEquals(3, security.aces().size());
        assertEquals(new WindowsSecurity.Ace(WindowsSecurity.ACCESS_ALLOWED_ACE_TYPE, 0, 0x1F01FF, "S-1-5-18"), security.aces().get(0));
        assertEquals(new WindowsSecurity.Ace(WindowsSecurity.ACCESS_DENIED_ACE_TYPE, 0x03, 0x116, "S-1-5-32-545"), security.aces().get(1));
        assertEquals(new WindowsSecurity.Ace(WindowsSecurity.ACCESS_ALLOWED_ACE_TYPE, WindowsSecurity.INHERIT_ONLY_ACE, 0x1200A9, "S-1-5-11"),
                security.aces().get(2));
    }

    @Test
    void anObjectEntry_HasNoPlainSid() {
        var security = WindowsSecurity.securityDescriptorFromSddl("O:BAD:(OA;;FA;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)");

        assertEquals(0x05, security.aces().getFirst().type());
        assertNull(security.aces().getFirst().sid());
    }

    @Test
    void noDacl_GrantsEveryoneFullControl_AndNoOwner_IsNull() {
        assertTrue(WindowsSecurity.securityDescriptorFromSddl("O:BAD:NO_ACCESS_CONTROL").grantsEveryoneFull());
        assertNull(WindowsSecurity.securityDescriptorFromSddl("D:(A;;FA;;;SY)").ownerSid());
    }

    @Test
    void invalidSddl_IsAnArgumentError() {
        assertThrows(IllegalArgumentException.class, () -> WindowsSecurity.securityDescriptorFromSddl("not SDDL"));
    }

    @Test
    void system32_IsOwnedByTrustedInstaller() throws IOException {
        var security = WindowsSecurity.securityDescriptorOf(systemDirectory());

        assertEquals(WindowsAccessRules.TRUSTED_INSTALLER, security.ownerSid());
        assertFalse(security.aces().isEmpty());
    }

    @Test
    void aMissingPath_IsAnIOException() {
        var missing = Path.of(System.getProperty("java.io.tmpdir"), "hkdfguard-missing-" + UUID.randomUUID()).toString();

        var ex = assertThrows(IOException.class, () -> WindowsSecurity.securityDescriptorOf(missing));
        assertFalse(ex instanceof NoSuchFileException);
        assertTrue(ex.getMessage().contains("error 2"), ex.getMessage());
    }

    @Test
    void fileAttributes_ReportsAFolder_AndInvalidForAMissingPath() {
        var attributes = WindowsSecurity.fileAttributes(systemDirectory());

        assertTrue((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0);
        assertEquals(0, attributes & WindowsSecurity.FILE_ATTRIBUTE_REPARSE_POINT);
        assertEquals(WindowsSecurity.INVALID_FILE_ATTRIBUTES, WindowsSecurity.fileAttributes(systemDirectory() + "\\hkdfguard-missing-" + UUID.randomUUID()));
    }

    @Test
    void canonicalSid_ReadsAliasesAndFullForms_AndRefusesTheRest() {
        assertEquals("S-1-5-32-544", WindowsSecurity.canonicalSid("BA"));
        assertEquals("S-1-5-18", WindowsSecurity.canonicalSid("S-1-5-18"));
        assertNull(WindowsSecurity.canonicalSid("not a SID"));
    }

    @Test
    void accountName_NamesWellKnownSids_AndNullForUnknownOnes() {
        var system = WindowsSecurity.accountName("S-1-5-18");
        assertNotNull(system);
        assertTrue(system.endsWith("\\SYSTEM"), system);

        assertNull(WindowsSecurity.accountName("S-1-5-21-1111111111-2222222222-3333333333-1005"));
        assertNull(WindowsSecurity.accountName("not a SID"));
    }
}
