package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;

/**
 * The macOS loader's system-call layer against the real filesystem and Security framework, the
 * installed libhkdfguard.dylib and the hkdfguard installed beside it, where they
 * are. Skipped off macOS; the tests that need an install are skipped without one. Test names follow
 * the Go port's TestDarwin_*. A native call that could raise a keychain dialog is made with
 * NativeTestEnvironment's deadline, so a dialog nobody answers fails the run rather than hanging it.
 */
@EnabledOnOs(value = OS.MAC, disabledReason = "macOS only.")
class MacOsNativeIntegrationTest {
    @Test
    void theInstalledLibrary_PassesEveryCheck() {
        var path = NativeTestEnvironment.assumeMacOsLibraryInstalled();
        var isSystem = path.equals(MacOsNativeLibraryLoader.systemPath());
        List<Long> owners = isSystem ? List.of(0L) : List.of(0L, MacOsNative.effectiveUserId());

        assertDoesNotThrow(() -> MacOsNativeLibraryLoader.verifyLocation(path, MacOsNative::status, owners));
        assertDoesNotThrow(() -> MacOsNativeLibraryLoader.verifySignature(path, MacOsNative::checkCodeSignature));
    }

    @Test
    void theInstalledLibrary_LoadsOnce_AndAnswersCalls() throws Exception {
        NativeTestEnvironment.assumeMacOsLibraryInstalled();

        var library = MacOsNativeLibraryLoader.load();
        assertNotNull(library);
        assertSame(library, MacOsNativeLibraryLoader.load()); // once per process

        // No KEK is provisioned for this name, so the library answers with an error status the
        // binding describes - which proves it loaded and ran.
        var binding = new MacOsHkdfGuardKmsLibrary();
        var result = NativeTestEnvironment.callWithKeychainTimeout("A wrap under an unprovisioned service",
                () -> binding.wrapDek(NativeTestEnvironment.UNPROVISIONED_SERVICE_NAME, new byte[32], new byte[512]));
        assertTrue(result.status() < 0, "wrap under an unprovisioned service returned status " + result.status());
        assertNotNull(binding.describeStatus(result.status()), "undescribed status " + result.status());
    }

    @Test
    void theTestService_AnswersItsFirstCall_WithoutAnUnansweredKeychainDialog() throws Exception {
        // assumeService makes the first call under the test service with a deadline, failing with
        // what to do about the keychain dialog instead of hanging; this one must then return too.
        NativeTestEnvironment.assumeMacOsLibraryInstalled();
        var service = NativeTestEnvironment.assumeService();

        var binding = new MacOsHkdfGuardKmsLibrary();
        var result = NativeTestEnvironment.callWithKeychainTimeout("A wrap under service '" + service + "'",
                () -> binding.wrapDek(service, new byte[32], new byte[512]));

        assertEquals(AbstractHkdfGuardKmsLibrary.OK, result.status(), () -> "wrap returned status " + result.status() + " (" + binding.describeStatus(result.status()) + ")");
    }

    @Test
    void theProvisioningTool_IsSignedByTheTeam_ButRefused() {
        // Installed beside the library and signed by the same team: only the identifier in the code
        // requirement tells them apart.
        var tool = Path.of(MacOsNativeLibraryLoader.SYSTEM_DIRECTORY, NativeTestEnvironment.MACOS_PROVISIONING_TOOL);
        Assumptions.assumeTrue(Files.isRegularFile(tool), tool + " is not installed.");

        var ex = assertThrows(SecurityException.class, () -> MacOsNativeLibraryLoader.verifySignature(tool.toString(), MacOsNative::checkCodeSignature));

        assertTrue(ex.getMessage().contains(MacOsNativeLibraryLoader.TEAM_ID), ex.getMessage());
    }

    @Test
    void anUnsignedFile_IsRefused(@TempDir Path directory) throws IOException {
        var path = Files.write(directory.resolve(MacOsNativeLibraryLoader.FILE_NAME), new byte[] {(byte) 0xCF, (byte) 0xFA, (byte) 0xED, (byte) 0xFE});

        assertThrows(SecurityException.class, () -> MacOsNativeLibraryLoader.verifySignature(path.toString(), MacOsNative::checkCodeSignature));
    }

    @Test
    void aUserWritableTemporaryDirectory_FailsTheLocationCheck(@TempDir Path directory) throws IOException {
        // The planting scenario: a correctly named file somewhere the system install check would
        // refuse. The temp directory is owned by this user, never root, so a system-owner check fails.
        var path = Files.write(directory.resolve(MacOsNativeLibraryLoader.FILE_NAME), new byte[0]);
        var resolved = path.toRealPath().toString(); // /var -> /private/var

        var ex = assertThrows(SecurityException.class, () -> MacOsNativeLibraryLoader.verifyLocation(resolved, MacOsNative::status, List.of(0L)));

        assertTrue(ex.getMessage().contains("owned by uid"), ex.getMessage());
    }

    @Test
    void probeDistinguishesMissingFromPresent() {
        assertEquals(0, MacOsNative.probe("/"));
        assertEquals(2, MacOsNative.probe("/definitely/not/here")); // ENOENT
    }

    @Test
    void theProvisioningTool_ReportsAnUnprovisionedService_AsAbsent() throws IOException, InterruptedException {
        var tool = NativeTestEnvironment.macOsProvisioningTool();
        Assumptions.assumeTrue(tool != null, "The provisioning tool is not installed.");

        var run = NativeTestEnvironment.runTool(tool, "status", "--service-name", NativeTestEnvironment.UNPROVISIONED_SERVICE_NAME);

        assertEquals(0, run.exitCode(), run::output);
        assertTrue(run.output().contains("kek: absent"), run::output);
    }

    @Test
    void theDefaultTestService_IsFoundOnlyWhenProvisioned() throws IOException, InterruptedException {
        var tool = NativeTestEnvironment.macOsProvisioningTool();
        Assumptions.assumeTrue(tool != null, "The provisioning tool is not installed.");
        var run = NativeTestEnvironment.runTool(tool, "status", "--service-name", NativeTestEnvironment.DEFAULT_SERVICE_NAME);
        assertEquals(0, run.exitCode(), run::output);

        var resolution = NativeTestEnvironment.macOsResolution();

        var provisioned = run.output().contains("kek: present");
        assertEquals(provisioned, resolution.service() != null, () -> "resolution " + resolution + ", but the tool reports provisioned = " + provisioned);
    }
}
