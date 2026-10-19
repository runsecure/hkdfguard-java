package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;

import io.github.runsecure.hkdfguard.keywrapping.v1.NativeLibraryNotFoundException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assumptions;

/**
 * Which provisioned service the native integration tests run against. Every platform's library
 * refuses to create a KEK during wrap/unwrap - one must be provisioned beforehand - so these tests
 * run only against a provisioned service and are reported as skipped otherwise. Once a service is
 * chosen, a missing or failing library is a test failure, never a silent pass.
 */
public final class NativeTestEnvironment {
    /**
     * Names a service already provisioned on this machine; its KEK is used, never created or
     * deleted. Always wins over {@link #DEFAULT_WINDOWS_SERVICE_NAME}, and is never skipped:
     * setting it means the native tests must run.
     */
    public static final String SERVICE_VARIABLE = "HKDFGUARD_TEST_SERVICE";

    /**
     * The Windows test KEK that scripts/provision-windows-test-key.ps1 (in this repository)
     * provisions. Used when {@link #SERVICE_VARIABLE} is unset and the installed library reports it
     * exists.
     */
    public static final String DEFAULT_WINDOWS_SERVICE_NAME = "com.hkdfguard.integration.test.221";

    /**
     * The macOS test KEK the other ports' scripts/provision-macos-test-key.sh provisions. Used when
     * {@link #SERVICE_VARIABLE} is unset and the installed hkdfguard-v1-initialize reports it
     * present.
     */
    public static final String DEFAULT_MACOS_SERVICE_NAME = "com.hkdfguard.integration.test.221";

    /**
     * The Linux test KEK the .NET port's scripts/provision-linux-test-key.sh provisions (with
     * {@code <name>.other} as the second service). Linux has no non-prompting way to ask whether a
     * KEK exists, so it is only used when named in {@link #SERVICE_VARIABLE}.
     */
    public static final String DEFAULT_LINUX_SERVICE_NAME = "com.hkdfguard.integration.test.221";

    /** Optional second provisioned service, for the cross-service isolation test. */
    public static final String OTHER_SERVICE_VARIABLE = "HKDFGUARD_TEST_SERVICE_OTHER";

    /** A valid service name (ASCII letters, digits, '.') that is never provisioned. */
    public static final String UNPROVISIONED_SERVICE_NAME = "hkdfguard.integrationtest.unprovisioned";

    /** The Linux policy file; its tpm.require_pinned_names allowlist is what some Linux tests need. */
    public static final String LINUX_POLICY_PATH = "/etc/hkdfguard/policy.toml";

    /** The Linux provisioning tool, from the hkdfguard package. */
    public static final String LINUX_CLI = "/usr/bin/hkdfguard";

    /** The macOS provisioning tool's file name, installed beside libhkdfguard_v1.dylib. */
    public static final String MACOS_PROVISIONING_TOOL = "hkdfguard-v1-initialize";

    /** Which service the native tests use, or why they are skipped. */
    record Resolution(String service, String skipReason) {
    }

    private static Resolution resolved;

    private NativeTestEnvironment() {
    }

    /** True on Windows. */
    public static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("windows");
    }

    /** True on Windows with the native library installed at its one supported location. */
    public static boolean windowsLibraryInstalled() {
        return isWindows() && Files.isRegularFile(Path.of(WindowsNativeLibraryLoader.installedPath()));
    }

    /** Skips the calling test unless {@link #windowsLibraryInstalled()}. */
    public static void assumeWindowsLibraryInstalled() {
        Assumptions.assumeTrue(isWindows(), "Windows only.");
        Assumptions.assumeTrue(windowsLibraryInstalled(),
                () -> "The native KMS library is not installed at " + WindowsNativeLibraryLoader.installedPath() + ".");
    }

    /** True on Linux. */
    public static boolean isLinux() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("linux");
    }

    /** Skips the calling test unless it runs on Linux. */
    public static void assumeLinux() {
        Assumptions.assumeTrue(isLinux(), "Linux only.");
    }

    /**
     * Where the libhkdfguard1 package installed the Linux library (the first of
     * LinuxNativeLibraryLoader's candidate locations that holds a file), or null if it isn't
     * installed, this isn't Linux, or no package is built for this architecture.
     */
    public static String linuxInstalledPath() {
        if (!isLinux())
            return null;
        try {
            return LinuxNativeLibraryLoader.candidatePaths(CpuArchitecture.current()).stream()
                    .filter(p -> Files.exists(Path.of(p)))
                    .findFirst()
                    .orElse(null);
        } catch (UnsupportedOperationException e) {
            return null; // no package for this architecture
        }
    }

    /** The installed Linux library's path, skipping the calling test when it isn't installed. */
    public static String assumeLinuxLibraryInstalled() {
        assumeLinux();
        var path = linuxInstalledPath();
        Assumptions.assumeTrue(path != null, "The libhkdfguard1 package is not installed.");
        return path;
    }

    /**
     * The provisioned service for a real call into the Linux library, skipping the calling test off
     * Linux, without the libhkdfguard1 package, or without a provisioned service - in that order,
     * as the .NET port's LinuxNativeIntegrationFact does.
     */
    public static String assumeLinuxNativeIntegration() {
        assumeLinuxLibraryInstalled();
        return assumeService();
    }

    /** The second provisioned service, skipping the calling test unless {@link #OTHER_SERVICE_VARIABLE} names one. */
    public static String assumeOtherService() {
        var other = read(OTHER_SERVICE_VARIABLE);
        Assumptions.assumeTrue(other != null, "Set " + OTHER_SERVICE_VARIABLE + " to a second provisioned service.");
        return other;
    }

    /**
     * Skips the calling test unless the Linux policy sets tpm.require_pinned_names = true, so a
     * service its allowlist doesn't name has no KEK.
     */
    public static void assumePinnedNamesAllowlist() {
        Assumptions.assumeTrue(linuxPolicyRequiresPinnedNames(),
                LINUX_POLICY_PATH + " does not set tpm.require_pinned_names = true (the .NET port's scripts/provision-linux-test-key.sh does).");
    }

    static boolean linuxPolicyRequiresPinnedNames() {
        try (var lines = Files.lines(Path.of(LINUX_POLICY_PATH))) {
            return lines.anyMatch(line -> line.replace(" ", "").equals("require_pinned_names=true"));
        } catch (IOException | UncheckedIOException | SecurityException e) {
            return false;
        }
    }

    /** Skips the calling test unless the hkdfguard package's {@link #LINUX_CLI} is installed. */
    public static void assumeLinuxCli() {
        Assumptions.assumeTrue(Files.isRegularFile(Path.of(LINUX_CLI)), LINUX_CLI + " is not installed (the hkdfguard package).");
    }

    /** True on macOS. */
    public static boolean isMacOs() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("mac");
    }

    /**
     * The install MacOsNativeLibraryLoader would choose - the system one, else this user's - or null
     * if neither is installed, it can't tell, or this isn't macOS.
     */
    public static String macOsInstalledPath() {
        if (!isMacOs())
            return null;
        try {
            return MacOsNativeLibraryLoader.choosePath(MacOsNative::probe, System.getProperty("user.home", "")).path();
        } catch (NativeLibraryNotFoundException | SecurityException e) {
            return null;
        }
    }

    /** The installed macOS library's path, skipping the calling test when it isn't installed. */
    public static String assumeMacOsLibraryInstalled() {
        Assumptions.assumeTrue(isMacOs(), "macOS only.");
        var path = macOsInstalledPath();
        Assumptions.assumeTrue(path != null, "The native KMS library is not installed at " + MacOsNativeLibraryLoader.systemPath() + " or ~/"
                + MacOsNativeLibraryLoader.USER_DIRECTORY_UNDER_HOME + ".");
        return path;
    }

    /**
     * The hkdfguard-v1-initialize installed beside the library MacOsNativeLibraryLoader would
     * choose, or null if there is none.
     */
    public static String macOsProvisioningTool() {
        var library = macOsInstalledPath();
        if (library == null)
            return null;
        var tool = Path.of(library).resolveSibling(MACOS_PROVISIONING_TOOL);
        return Files.isRegularFile(tool) ? tool.toString() : null;
    }

    /** Skips the calling test unless this platform's native library is installed where its loader looks. */
    public static void assumeLibraryInstalled() {
        if (isWindows())
            assumeWindowsLibraryInstalled();
        else if (isLinux())
            assumeLinuxLibraryInstalled();
        else if (isMacOs())
            assumeMacOsLibraryInstalled();
        else
            Assumptions.abort("No native KMS library is built for " + System.getProperty("os.name") + ".");
    }

    /** What a tool printed (stdout and stderr together), and its exit code. */
    public record ToolRun(int exitCode, String output) {
    }

    /**
     * Runs a provisioning tool with no input and a 60-second limit. Output goes to a file, so a
     * tool that never exits can't block the test on a pipe.
     */
    public static ToolRun runTool(String tool, String... arguments) throws IOException, InterruptedException {
        var command = new ArrayList<String>();
        command.add(tool);
        command.addAll(List.of(arguments));
        var output = Files.createTempFile("hkdfguard-tool-", ".out");
        try {
            var process = new ProcessBuilder(command)
                    .redirectErrorStream(true)
                    .redirectOutput(output.toFile())
                    .start();
            process.getOutputStream().close(); // no input: a prompt reads end of file
            if (!process.waitFor(60, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                throw new IllegalStateException(tool + " did not exit within 60 seconds.");
            }
            return new ToolRun(process.exitValue(), Files.readString(output));
        } finally {
            Files.deleteIfExists(output);
        }
    }

    /**
     * How the macOS default test service resolves: the installed hkdfguard-v1-initialize, which
     * created the KEK and so is on its keychain item's access list, is asked whether it is present -
     * asking the library from this process could prompt. "kek: absent" skips; "kek: present", or
     * any failure to ask, runs the tests, so a real failure is reported.
     */
    static Resolution macOsResolution(String defaultService) {
        if (macOsInstalledPath() == null)
            return new Resolution(null, "The native KMS library is not installed at " + MacOsNativeLibraryLoader.systemPath() + " or ~/"
                    + MacOsNativeLibraryLoader.USER_DIRECTORY_UNDER_HOME + ".");

        var tool = macOsProvisioningTool();
        if (tool == null)
            return new Resolution(defaultService, "");

        ToolRun run;
        try {
            run = runTool(tool, "status", "--service-name", defaultService);
        } catch (IOException | RuntimeException e) {
            return new Resolution(defaultService, "");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Resolution(defaultService, "");
        }
        if (run.exitCode() == 0 && run.output().contains("kek: absent"))
            return new Resolution(null, "The test KEK '" + defaultService + "' is not provisioned. Run " + MACOS_PROVISIONING_TOOL
                    + " provision --service-name " + defaultService + ", or set " + SERVICE_VARIABLE + " to a provisioned service.");
        return new Resolution(defaultService, "");
    }

    /** The provisioned service, skipping the calling test when there is none. */
    public static String assumeService() {
        var resolution = resolve();
        Assumptions.assumeTrue(resolution.service() != null, resolution.skipReason());
        return resolution.service();
    }

    /** The second service for isolation tests: a provisioned one if named, else one never provisioned. */
    public static String otherServiceName() {
        var other = read(OTHER_SERVICE_VARIABLE);
        return other != null ? other : UNPROVISIONED_SERVICE_NAME;
    }

    private static synchronized Resolution resolve() {
        if (resolved == null)
            resolved = doResolve();
        return resolved;
    }

    private static Resolution doResolve() {
        var explicit = read(SERVICE_VARIABLE);
        if (explicit != null)
            return new Resolution(explicit, "");

        if (isMacOs())
            return macOsResolution(DEFAULT_MACOS_SERVICE_NAME);

        if (!isWindows())
            return new Resolution(null, "Set " + SERVICE_VARIABLE + " to a service provisioned with hkdfguard provision to run native integration tests. On a Linux TPM host, "
                    + "the .NET port's sudo scripts/provision-linux-test-key.sh provisions " + DEFAULT_LINUX_SERVICE_NAME + ".");

        if (!windowsLibraryInstalled())
            return new Resolution(null, "The native KMS library is not installed at " + WindowsNativeLibraryLoader.installedPath() + ".");

        int[] answer;
        try {
            answer = queryKekExists(DEFAULT_WINDOWS_SERVICE_NAME);
        } catch (RuntimeException e) {
            // Installed, but it couldn't even be asked (it failed verification, say): run the
            // tests so that failure is reported.
            return new Resolution(DEFAULT_WINDOWS_SERVICE_NAME, "");
        }

        var status = answer[0];
        var exists = answer[1] != 0;
        if (status == 0 && exists)
            return new Resolution(DEFAULT_WINDOWS_SERVICE_NAME, "");
        if (status == 0 || status == AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND)
            return new Resolution(null, "The test KEK '" + DEFAULT_WINDOWS_SERVICE_NAME + "' is not provisioned. Run scripts/provision-windows-test-key.ps1 from an elevated PowerShell, or set "
                    + SERVICE_VARIABLE + " to a provisioned service.");
        if (status == AbstractHkdfGuardKmsLibrary.ERR_KEK_ACCESS_DENIED)
            return new Resolution(null, "The test KEK '" + DEFAULT_WINDOWS_SERVICE_NAME
                    + "' exists, but this account may not use it. Add it to the HkdfGuardUsers group (then sign out and in), or run the tests elevated.");
        return new Resolution(DEFAULT_WINDOWS_SERVICE_NAME, "");
    }

    /**
     * Asks the installed Windows library whether a service's KEK exists, through its
     * {@code hkdfguard_kek_exists(const char* service, int32_t* out_exists)} export, loaded through
     * the same verified loader production uses.
     *
     * @return {status, exists}
     */
    @SuppressWarnings("restricted")
    static int[] queryKekExists(String service) {
        var library = WindowsNativeLibraryLoader.load();
        var kekExists = Linker.nativeLinker().downcallHandle(WindowsNativeLibraryLoader.export(library, "hkdfguard_kek_exists"),
                FunctionDescriptor.of(JAVA_INT, ADDRESS, ADDRESS));
        try (var arena = Arena.ofConfined()) {
            var exists = arena.allocate(JAVA_INT);
            var status = (int) kekExists.invokeExact(arena.allocateFrom(service), exists);
            return new int[] {status, status == 0 ? exists.get(JAVA_INT, 0) : 0};
        } catch (RuntimeException | Error e) {
            throw e;
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    /**
     * A new temporary folder for key files the native library reads, by its real, long path.
     * hkdfguard_open_file refuses an 8.3 short name or a link anywhere in a path, and Windows can
     * hand out the temp folder in short form (for example C:\Users\RUNNER~1\... on GitHub-hosted
     * runners); toRealPath expands every short component and resolves any link.
     */
    public static Path createTempDirectory(String prefix) throws IOException {
        return Files.createTempDirectory(prefix).toRealPath();
    }

    private static String read(String variable) {
        var value = System.getenv(variable);
        return value == null || value.isEmpty() ? null : value;
    }
}
