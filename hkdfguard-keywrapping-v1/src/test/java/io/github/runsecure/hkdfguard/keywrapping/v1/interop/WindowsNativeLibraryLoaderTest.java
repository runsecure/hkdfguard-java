package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.keywrapping.v1.NativeLibraryNotFoundException;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class WindowsNativeLibraryLoaderTest {
    private static final String USERS = "S-1-5-32-545";

    // Carried by every Artifact Signing leaf, whoever the customer.
    private static final String ARTIFACT_SIGNING_EKU = "1.3.6.1.4.1.311.97.1.0";

    // The genuine signing certificate's EKUs.
    private static final List<String> GENUINE_EKUS =
            List.of(ARTIFACT_SIGNING_EKU, WindowsNativeLibraryLoader.CODE_SIGNING_EKU, WindowsNativeLibraryLoader.EXPECTED_PROFILE_EKU);

    private static Win32.SecurityDescriptorInfo sddl(String sddl) {
        return Win32.securityDescriptorFromSddl(sddl);
    }

    // --- Location -------------------------------------------------------------------------------

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void installedPath_IsTheFixedProgramFilesLocation() {
        var programFiles = System.getenv("ProgramFiles");

        assertEquals(Path.of(programFiles, "HkdfGuard", "v1", "HkdfGuard.dll").toString().toLowerCase(Locale.ROOT),
                WindowsNativeLibraryLoader.installedPath().toLowerCase(Locale.ROOT));
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void load_WhenTheFileIsMissing_ThrowsNotFound_NamingTheOnlySupportedPath() {
        var missing = Path.of(System.getProperty("java.io.tmpdir"), "hkdfguard-missing-" + UUID.randomUUID(), "HkdfGuard.dll").toString();

        var ex = assertThrows(NativeLibraryNotFoundException.class, () -> WindowsNativeLibraryLoader.load(missing, WindowsNativeLibraryLoader.EXPECTED_PUBLISHER));

        assertTrue(ex.getMessage().contains(missing));
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void load_FromAUserWritableFolder_IsRefused_BeforeAnythingIsLoaded() throws IOException {
        // The DLL-planting scenario: a correctly named file in a folder the current user controls.
        var dir = Files.createTempDirectory("hkdfguard-plant-");
        try {
            var planted = dir.resolve(WindowsNativeLibraryLoader.FILE_NAME);
            Files.write(planted, new byte[] {0x4D, 0x5A});

            assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.load(planted.toString(), WindowsNativeLibraryLoader.EXPECTED_PUBLISHER));
        } finally {
            try (var files = Files.walk(dir)) {
                files.sorted(java.util.Comparator.reverseOrder()).forEach(p -> p.toFile().delete());
            }
        }
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void verifyTrustedOnly_TrustedOwnerAndReadOnlyForEveryoneElse_Passes() {
        var security = sddl("O:SYD:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;BU)");

        assertDoesNotThrow(() -> WindowsNativeLibraryLoader.verifyTrustedOnly(security, "test"));
    }

    @ParameterizedTest
    @EnabledOnOs(OS.WINDOWS)
    @ValueSource(strings = {
            "0x2",      // FILE_WRITE_DATA
            "0x4",      // FILE_APPEND_DATA
            "0x10",     // FILE_WRITE_EA
            "0x40",     // FILE_DELETE_CHILD
            "0x10000",  // DELETE
            "WD",       // WRITE_DAC (ChangePermissions)
            "WO",       // WRITE_OWNER (TakeOwnership)
            "0x1301bf", // Modify
    })
    void verifyTrustedOnly_AnyWriteRightForAnUntrustedPrincipal_IsRefused(String right) {
        var security = sddl("O:BAD:(A;;" + right + ";;;BU)");

        var ex = assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifyTrustedOnly(security, "test"));

        assertTrue(ex.getMessage().contains(USERS), ex.getMessage());
    }

    @ParameterizedTest
    @EnabledOnOs(OS.WINDOWS)
    @ValueSource(strings = {"GA", "GW"})
    void verifyTrustedOnly_UnmappedGenericWriteForAnUntrustedPrincipal_IsRefused(String genericRight) {
        var security = sddl("O:SYD:(A;;FA;;;SY)(A;;" + genericRight + ";;;AU)");

        assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifyTrustedOnly(security, "test"));
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void verifyTrustedOnly_AnUntrustedOwner_IsRefused() {
        // An owner can always rewrite the ACL, whatever it currently says.
        var security = sddl("O:BUD:(A;;FA;;;SY)");

        assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifyTrustedOnly(security, "test"));
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void verifyTrustedOnly_NoOwnerAtAll_IsRefused() {
        var security = sddl("D:(A;;FA;;;SY)");

        var ex = assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifyTrustedOnly(security, "test"));

        assertTrue(ex.getMessage().contains("an unknown principal"));
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void verifyTrustedOnly_AnOwnerSidWithNoAccount_IsRefused_AndNamedBySid() {
        // A SID that maps to no account here, e.g. left behind by a deleted user.
        var orphan = "S-1-5-21-1-2-3-4242";
        var security = sddl("O:" + orphan + "D:(A;;FA;;;SY)");

        var ex = assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifyTrustedOnly(security, "test"));

        assertTrue(ex.getMessage().contains(orphan));
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void verifyTrustedOnly_ATrustedOwnerIsNamedByAccountAndSid() {
        var security = sddl("O:SYD:(A;;FA;;;BU)");

        var ex = assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifyTrustedOnly(security, "test"));

        assertTrue(ex.getMessage().contains("\\") && ex.getMessage().contains("(" + USERS + ")"), ex.getMessage());
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void verifyTrustedOnly_NoDaclAtAll_IsRefused() {
        // A missing (NULL) DACL grants every user full control.
        var security = sddl("O:SYD:NO_ACCESS_CONTROL");

        var ex = assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifyTrustedOnly(security, "test"));

        assertTrue(ex.getMessage().contains("no DACL"));
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void verifyTrustedOnly_InheritOnlyAndDenyEntries_AreIgnored() {
        // A folder like Program Files: Users get full control of what they create beneath it
        // (inherit-only, so not of the folder itself), plus an explicit Deny.
        var security = sddl("O:SYD:(D;;FW;;;BU)(A;;FA;;;SY)(A;OICIIO;FA;;;BU)(A;;FR;;;BU)");

        assertDoesNotThrow(() -> WindowsNativeLibraryLoader.verifyTrustedOnly(security, "test"));
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void verifyTrustedOnly_AnAllowObjectAce_FailsClosed() {
        var security = sddl("O:SYD:(OA;;FA;bf967aba-0de6-11d0-a285-00aa003049e2;;BU)");

        assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifyTrustedOnly(security, "test"));
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void verifyDriveRoot_ADefaultSystemDriveAcl_Passes() {
        // As a default C:\: Authenticated Users may create folders in the root (0x4, AD) and get
        // Modify on what they create (inherit-only) - neither lets them rename an existing folder.
        var security = sddl("O:SYD:(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;BU)(A;OICIIO;SDGXGWGR;;;AU)(A;;0x4;;;AU)");

        assertDoesNotThrow(() -> WindowsNativeLibraryLoader.verifyDriveRoot(security, "C:\\"));
    }

    @ParameterizedTest
    @EnabledOnOs(OS.WINDOWS)
    @ValueSource(strings = {
            "0x40", // FILE_DELETE_CHILD: rename or delete any folder beneath, e.g. Program Files
            "WD",   // WRITE_DAC: grant itself delete-child
            "WO",   // WRITE_OWNER: take ownership, then the same
            "GA",   // GENERIC_ALL
            "FA",   // FILE_ALL_ACCESS
    })
    void verifyDriveRoot_ARightThatCouldRenameAFolderBeneath_IsRefused(String right) {
        var security = sddl("O:SYD:(A;OICI;FA;;;SY)(A;;" + right + ";;;BU)");

        var ex = assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifyDriveRoot(security, "C:\\"));

        assertTrue(ex.getMessage().contains(USERS));
    }

    @ParameterizedTest
    @EnabledOnOs(OS.WINDOWS)
    @ValueSource(strings = {
            "0x1", // FILE_ADD_FILE
            "0x4", // FILE_ADD_SUBDIRECTORY
            "GW",  // GENERIC_WRITE maps to neither delete-child nor ACL rights
    })
    void verifyDriveRoot_RightsThatOnlyCreateNewEntries_AreAllowed(String right) {
        var security = sddl("O:SYD:(A;OICI;FA;;;SY)(A;;" + right + ";;;BU)");

        assertDoesNotThrow(() -> WindowsNativeLibraryLoader.verifyDriveRoot(security, "C:\\"));
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void verifyDriveRoot_AnUntrustedOwner_IsRefused() {
        var security = sddl("O:BUD:(A;OICI;FA;;;SY)");

        assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifyDriveRoot(security, "C:\\"));
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void verifyNotReparsePoint_AJunction_IsRefused() throws Exception {
        // Junctions need no privilege to create, unlike symbolic links.
        var target = Files.createTempDirectory("hkdfguard-target-");
        var junction = Path.of(System.getProperty("java.io.tmpdir"), "hkdfguard-junction-" + UUID.randomUUID());
        try {
            var mklink = new ProcessBuilder("cmd.exe", "/c", "mklink", "/J", junction.toString(), target.toString())
                    .redirectErrorStream(true).start();
            mklink.getInputStream().readAllBytes();
            assertEquals(0, mklink.waitFor());

            assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifyNotReparsePoint(junction.toString()));
            assertDoesNotThrow(() -> WindowsNativeLibraryLoader.verifyNotReparsePoint(target.toString()));
        } finally {
            Files.deleteIfExists(junction);
            Files.deleteIfExists(target);
        }
    }

    // --- Image kind -----------------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource({"X64,0x8664", "ARM64,0xAA64", "X86,0x014C"})
    void verifyImageKind_ADllForThisProcessArchitecture_Passes(CpuArchitecture process, String machine) {
        assertDoesNotThrow(() -> WindowsNativeLibraryLoader.verifyImageKind("test",
                WindowsNativeLibraryLoader.IMAGE_FILE_DLL | WindowsNativeLibraryLoader.IMAGE_FILE_EXECUTABLE_IMAGE,
                Integer.decode(machine), process));
    }

    @Test
    void verifyImageKind_AnExecutable_IsRefused() {
        // e.g. hkdfguard.exe renamed into place: signed by the same profile.
        var ex = assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifyImageKind("test",
                WindowsNativeLibraryLoader.IMAGE_FILE_EXECUTABLE_IMAGE, WindowsNativeLibraryLoader.IMAGE_FILE_MACHINE_AMD64, CpuArchitecture.X64));

        assertTrue(ex.getMessage().contains("not a DLL"));
    }

    @ParameterizedTest
    @CsvSource({"X64,0xAA64", "ARM64,0x8664", "X64,0x014C", "OTHER,0x0000"})
    void verifyImageKind_ADllForAnotherArchitecture_IsRefused(CpuArchitecture process, String machine) {
        assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifyImageKind("test",
                WindowsNativeLibraryLoader.IMAGE_FILE_DLL | WindowsNativeLibraryLoader.IMAGE_FILE_EXECUTABLE_IMAGE,
                Integer.decode(machine), process));
    }

    @Test
    void verifyImageKind_AFileThatIsNotAPeImage_FailsClosedWithSecurityException() throws IOException {
        var path = Files.createTempFile("hkdfguard-", ".dll");
        try {
            Files.write(path, new byte[] {0x4D, 0x5A, (byte) 0x90, 0x00});

            assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifyImageKind(path.toString()));
        } finally {
            Files.delete(path);
        }
    }

    // --- Signer -------------------------------------------------------------------------------

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void verifySignature_AnUnsignedFile_IsRefused() throws IOException {
        var path = Files.createTempFile("hkdfguard-", ".dll");
        try {
            Files.write(path, new byte[] {0x4D, 0x5A, (byte) 0x90, 0x00});

            assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifySignature(path.toString(), WindowsNativeLibraryLoader.EXPECTED_PUBLISHER));
        } finally {
            Files.delete(path);
        }
    }

    @Test
    void verifySignerIdentity_ThePinnedRootProfileAndPublisher_Passes() {
        assertDoesNotThrow(() -> verifySignerIdentity(GENUINE_EKUS, WindowsNativeLibraryLoader.EXPECTED_PUBLISHER, WindowsNativeLibraryLoader.EXPECTED_ROOT_SHA256));
    }

    @Test
    void verifySignerIdentity_TheRootHashInLowerCase_Passes() {
        assertDoesNotThrow(() -> verifySignerIdentity(GENUINE_EKUS, WindowsNativeLibraryLoader.EXPECTED_PUBLISHER,
                WindowsNativeLibraryLoader.EXPECTED_ROOT_SHA256.toLowerCase(Locale.ROOT)));
    }

    @Test
    void verifySignerIdentity_AnotherRoot_IsRefused() {
        // e.g. a root a non-administrator added to their own CurrentUser\Root, issuing the same subject.
        var otherRoot = "A".repeat(64);

        var ex = assertThrows(SecurityException.class, () -> verifySignerIdentity(GENUINE_EKUS, WindowsNativeLibraryLoader.EXPECTED_PUBLISHER, otherRoot));

        assertTrue(ex.getMessage().contains(otherRoot));
    }

    @Test
    void verifySignerIdentity_NoProfileEku_IsRefused() {
        var ex = assertThrows(SecurityException.class, () -> verifySignerIdentity(
                List.of(WindowsNativeLibraryLoader.CODE_SIGNING_EKU, ARTIFACT_SIGNING_EKU),
                WindowsNativeLibraryLoader.EXPECTED_PUBLISHER, WindowsNativeLibraryLoader.EXPECTED_ROOT_SHA256));

        assertTrue(ex.getMessage().contains(WindowsNativeLibraryLoader.EXPECTED_PROFILE_EKU));
    }

    @Test
    void verifySignerIdentity_AnotherArtifactSigningProfile_IsRefused() {
        // Another Artifact Signing customer's leaf: same root, same shared EKU, its own profile EKU.
        var ex = assertThrows(SecurityException.class, () -> verifySignerIdentity(
                List.of(ARTIFACT_SIGNING_EKU, WindowsNativeLibraryLoader.CODE_SIGNING_EKU, "1.3.6.1.4.1.311.97.1.2.3.4"),
                WindowsNativeLibraryLoader.EXPECTED_PUBLISHER, WindowsNativeLibraryLoader.EXPECTED_ROOT_SHA256));

        assertTrue(ex.getMessage().contains(WindowsNativeLibraryLoader.EXPECTED_PROFILE_EKU));
    }

    @Test
    void verifySignerIdentity_NoCodeSigningEku_IsRefused() {
        var ex = assertThrows(SecurityException.class, () -> verifySignerIdentity(
                List.of(ARTIFACT_SIGNING_EKU, WindowsNativeLibraryLoader.EXPECTED_PROFILE_EKU),
                WindowsNativeLibraryLoader.EXPECTED_PUBLISHER, WindowsNativeLibraryLoader.EXPECTED_ROOT_SHA256));

        assertTrue(ex.getMessage().contains(WindowsNativeLibraryLoader.CODE_SIGNING_EKU));
    }

    @Test
    void verifySignerIdentity_NoEkusAtAll_IsRefused() {
        assertThrows(SecurityException.class, () -> verifySignerIdentity(List.of(), WindowsNativeLibraryLoader.EXPECTED_PUBLISHER,
                WindowsNativeLibraryLoader.EXPECTED_ROOT_SHA256));
    }

    @Test
    void verifySignerIdentity_AnotherSubject_IsRefused_EvenWithThePinnedRootAndProfile() {
        var ex = assertThrows(SecurityException.class, () -> verifySignerIdentity(GENUINE_EKUS, "CN=Someone Else",
                WindowsNativeLibraryLoader.EXPECTED_ROOT_SHA256));

        assertTrue(ex.getMessage().contains("not the expected HkdfGuard publisher"));
    }

    @Test
    void verifySignature_WhenTheSignerCantBeRead_FailsClosedWithSecurityException() {
        var cause = new IllegalStateException("no chain");

        var ex = assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifySignature("test",
                WindowsNativeLibraryLoader.EXPECTED_PUBLISHER, path -> {
                    throw cause;
                }));

        assertSame(cause, ex.getCause());
    }

    @Test
    void verifySignature_ASecurityExceptionFromTheReader_IsNotWrapped() {
        var refusal = new SecurityException("untrusted");

        var ex = assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifySignature("test",
                WindowsNativeLibraryLoader.EXPECTED_PUBLISHER, path -> {
                    throw refusal;
                }));

        assertSame(refusal, ex);
    }

    @Test
    void verifySignature_AppliesTheSignerPolicyToWhatTheReaderReturns() {
        var signer = new WindowsNativeLibraryLoader.VerifiedSigner(WindowsNativeLibraryLoader.EXPECTED_PUBLISHER, GENUINE_EKUS, "A".repeat(64));

        assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifySignature("test",
                WindowsNativeLibraryLoader.EXPECTED_PUBLISHER, path -> signer));
    }

    @Test
    void windowsSubjectName_FormatsTheExpectedPublisherExactlyAsWindowsDoes() {
        // Encoded in the usual order, least specific first; shown most specific first.
        var name = new X500NameBuilder(BCStyle.INSTANCE)
                .addRDN(BCStyle.C, "US").addRDN(BCStyle.ST, "co").addRDN(BCStyle.L, "Littleton")
                .addRDN(BCStyle.O, "Torin Blair").addRDN(BCStyle.CN, "Torin Blair").build();

        assertEquals(WindowsNativeLibraryLoader.EXPECTED_PUBLISHER, WindowsNativeLibraryLoader.windowsSubjectName(name));
    }

    @Test
    void windowsSubjectName_QuotesValuesWithSpecialCharacters() {
        X500Name name = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.O, "Acme, Inc.").addRDN(BCStyle.CN, "Build \"Bot\"").build();

        assertEquals("CN=\"Build \"\"Bot\"\"\", O=\"Acme, Inc.\"", WindowsNativeLibraryLoader.windowsSubjectName(name));
    }

    private static void verifySignerIdentity(List<String> leafEkuOids, String leafSubject, String rootSha256) {
        WindowsNativeLibraryLoader.verifySignerIdentity("test", leafSubject, leafEkuOids, rootSha256, WindowsNativeLibraryLoader.EXPECTED_PUBLISHER);
    }

    // --- Version floor --------------------------------------------------------------------------

    @ParameterizedTest
    @CsvSource({"0,9,0", "0,9,1", "0,10,0", "1,0,0"})
    void verifyMinimumVersion_TheMinimumOrLater_Passes(int major, int minor, int patch) {
        assertDoesNotThrow(() -> WindowsNativeLibraryLoader.verifyMinimumVersion("test", new int[] {major, minor, patch}));
    }

    @ParameterizedTest
    @CsvSource({"0,8,9", "0,8,65535", "0,0,0"})
    void verifyMinimumVersion_AnOlderVersion_IsRefused(int major, int minor, int patch) {
        var e = assertThrows(SecurityException.class,
                () -> WindowsNativeLibraryLoader.verifyMinimumVersion("test", new int[] {major, minor, patch}));

        assertTrue(e.getMessage().contains("older than the minimum"), e.getMessage());
    }

    @Test
    void verifyMinimumVersion_NoVersionResource_IsRefused() {
        var e = assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifyMinimumVersion("test", null));

        assertTrue(e.getMessage().contains("no readable version resource"), e.getMessage());
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void fileVersion_AFileWithNoVersionResource_IsNull() throws IOException {
        var path = Files.createTempFile("hkdfguard", ".dll");
        try {
            Files.write(path, "MZ not really a PE image".getBytes(StandardCharsets.US_ASCII));

            assertEquals(null, Win32.fileVersion(path.toString()));
        } finally {
            Files.delete(path);
        }
    }

    @Test
    void fileVersion_TheInstalledLibrary_IsAtLeastTheMinimum() {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();

        var version = Win32.fileVersion(WindowsNativeLibraryLoader.installedPath());

        assertNotEquals(null, version);
        assertDoesNotThrow(() -> WindowsNativeLibraryLoader.verifyMinimumVersion(WindowsNativeLibraryLoader.installedPath(), version));
    }

    // --- The module Windows mapped --------------------------------------------------------------

    @ParameterizedTest
    @EnabledOnOs(OS.WINDOWS)
    @ValueSource(strings = {
            "C:\\Program Files\\HkdfGuard\\v1\\HkdfGuard.dll",
            "c:\\program files\\hkdfguard\\v1\\hkdfguard.DLL",
            "\\\\?\\C:\\Program Files\\HkdfGuard\\v1\\HkdfGuard.dll"})
    void verifyLoadedModule_TheVerifiedFileItself_Passes_WhateverItsCaseOrLongPathPrefix(String loaded) {
        assertDoesNotThrow(() -> WindowsNativeLibraryLoader.verifyLoadedModule("C:\\Program Files\\HkdfGuard\\v1\\HkdfGuard.dll", loaded));
    }

    @ParameterizedTest
    @EnabledOnOs(OS.WINDOWS)
    @ValueSource(strings = {
            "C:\\Users\\someone\\AppData\\Local\\Temp\\HkdfGuard.dll", // the same name, loaded earlier from elsewhere
            "C:\\app\\app.exe.local\\HkdfGuard.dll", // DLL redirection
            "C:\\Program Files\\HkdfGuard\\v2\\HkdfGuard.dll",
            "\\\\?\\UNC\\server\\share\\HkdfGuard.dll"})
    void verifyLoadedModule_AModuleMappedFromAnyOtherFile_IsRefused(String loaded) {
        var verified = "C:\\Program Files\\HkdfGuard\\v1\\HkdfGuard.dll";

        var e = assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifyLoadedModule(verified, loaded));

        assertTrue(e.getMessage().contains(verified) && e.getMessage().contains(loaded), e.getMessage());
    }

    // --- Against the installed library ----------------------------------------------------------

    @Test
    void load_TheInstalledLibrary_IsTheFileWindowsMapped() {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();

        var library = WindowsNativeLibraryLoader.load();

        assertEquals(WindowsNativeLibraryLoader.installedPath().toLowerCase(Locale.ROOT),
                Win32.moduleFileName(library).toLowerCase(Locale.ROOT));
    }

    @Test
    void verifyImageKind_TheInstalledLibrary_Passes() {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();

        assertDoesNotThrow(() -> WindowsNativeLibraryLoader.verifyImageKind(WindowsNativeLibraryLoader.installedPath()));
    }

    @Test
    void theInstalledProvisioningTool_PassesTheSignerChecks_ButIsRefusedAsNotADll() {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();
        // Installed beside the library and signed under the same profile: only the image check
        // tells them apart.
        var tool = Path.of(WindowsNativeLibraryLoader.installedPath()).resolveSibling("hkdfguard.exe").toString();
        assertTrue(Files.isRegularFile(Path.of(tool)), tool + " is installed with the library.");

        assertDoesNotThrow(() -> WindowsNativeLibraryLoader.verifySignature(tool, WindowsNativeLibraryLoader.EXPECTED_PUBLISHER));
        assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifyImageKind(tool));
    }

    @Test
    void readVerifiedSigner_TheInstalledLibrary_ChainsToThePinnedRoot_WithTheProfileEku() {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();
        // The chain WinVerifyTrust validated, not one built separately.
        var signer = WindowsNativeLibraryLoader.readVerifiedSigner(WindowsNativeLibraryLoader.installedPath());

        assertEquals(WindowsNativeLibraryLoader.EXPECTED_PUBLISHER, signer.leafSubject());
        assertEquals(WindowsNativeLibraryLoader.EXPECTED_ROOT_SHA256, signer.rootSha256());
        assertTrue(signer.leafEkuOids().contains(WindowsNativeLibraryLoader.CODE_SIGNING_EKU));
        assertTrue(signer.leafEkuOids().contains(WindowsNativeLibraryLoader.EXPECTED_PROFILE_EKU));
    }

    @Test
    void verifyLocation_TheInstalledLibrary_Passes() {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();

        assertDoesNotThrow(() -> WindowsNativeLibraryLoader.verifyLocation(WindowsNativeLibraryLoader.installedPath()));
    }

    @Test
    void verifySignature_ValidButFromAnotherPublisher_IsRefused() {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();

        var ex = assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifySignature(WindowsNativeLibraryLoader.installedPath(), "CN=Someone Else"));

        assertTrue(ex.getMessage().contains("not the expected HkdfGuard publisher"));
    }

    @Test
    void verifySignature_ATamperedCopy_IsRefused() throws IOException {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();
        var copy = Files.createTempFile("hkdfguard-", ".dll");
        try {
            var bytes = Files.readAllBytes(Path.of(WindowsNativeLibraryLoader.installedPath()));
            bytes[bytes.length / 2] ^= (byte) 0xFF; // inside the signed image, not the signature itself
            Files.write(copy, bytes);

            assertThrows(SecurityException.class, () -> WindowsNativeLibraryLoader.verifySignature(copy.toString(), WindowsNativeLibraryLoader.EXPECTED_PUBLISHER));
        } finally {
            Files.delete(copy);
        }
    }

    @Test
    void load_TheInstalledLibrary_ReturnsTheSameHandleEveryTime() {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();

        var first = WindowsNativeLibraryLoader.load();
        var second = WindowsNativeLibraryLoader.load();

        assertNotEquals(0, first.address());
        assertEquals(first.address(), second.address());
    }

    @Test
    void verifySignature_TheInstalledLibrary_IsValidAndFromTheExpectedPublisher() {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();

        assertDoesNotThrow(() -> WindowsNativeLibraryLoader.verifySignature(WindowsNativeLibraryLoader.installedPath(), WindowsNativeLibraryLoader.EXPECTED_PUBLISHER));
    }

    @Test
    void load_TheInstalledLibrary_MapsTheFixedProgramFilesFile() throws Throwable {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();
        // Worked out independently of the loader: %ProgramFiles%\HkdfGuard\v1\HkdfGuard.dll - and
        // the module Windows really mapped for the handle load returned is that file.
        var expected = Path.of(System.getenv("ProgramFiles"), "HkdfGuard", "v1", "HkdfGuard.dll").toString();

        var mapped = Kernel32.moduleFileName(WindowsNativeLibraryLoader.load());

        assertEquals(expected.toLowerCase(Locale.ROOT), mapped.toLowerCase(Locale.ROOT));
    }

    @Test
    void kekExists_AnswersForAnUnprovisionedService() {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();

        var answer = NativeTestEnvironment.queryKekExists(NativeTestEnvironment.UNPROVISIONED_SERVICE_NAME);

        assertEquals(0, answer[1], "an unprovisioned service's KEK exists");
        assertTrue(answer[0] == AbstractHkdfGuardKmsLibrary.OK || new WindowsHkdfGuardKmsLibrary().describeStatus(answer[0]) != null,
                "undescribed status " + answer[0]);
    }

    /** GetModuleFileNameW, for which file a loaded module came from. */
    @SuppressWarnings("restricted") // Test-only native calls; the tests run with --enable-native-access.
    private static final class Kernel32 {
        private static final int MAX_PATH_CHARS = 32768;

        static String moduleFileName(MemorySegment module) throws Throwable {
            var linker = Linker.nativeLinker();
            var kernel32 = SymbolLookup.libraryLookup("kernel32.dll", Arena.global());
            // DWORD GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
            var getModuleFileName = linker.downcallHandle(kernel32.find("GetModuleFileNameW").orElseThrow(),
                    FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS, JAVA_INT));
            try (var arena = Arena.ofConfined()) {
                var buffer = arena.allocate((long) MAX_PATH_CHARS * 2);
                var length = (int) getModuleFileName.invokeExact(module, buffer, MAX_PATH_CHARS);
                assertTrue(length > 0 && length < MAX_PATH_CHARS, "GetModuleFileNameW returned " + length);
                return new String(buffer.asSlice(0, length * 2L).toArray(JAVA_BYTE), StandardCharsets.UTF_16LE);
            }
        }
    }

    @Test
    void theWindowsBinding_CallsIntoTheInstalledLibrary() {
        NativeTestEnvironment.assumeWindowsLibraryInstalled();
        // No KEK is provisioned for this name, so the library answers with an error status -
        // which proves it loaded and ran.
        var library = new WindowsHkdfGuardKmsLibrary();

        var result = library.wrapDek(NativeTestEnvironment.UNPROVISIONED_SERVICE_NAME, new byte[32], new byte[512]);

        assertTrue(result.status() < 0);
    }
}
