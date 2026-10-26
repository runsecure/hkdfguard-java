package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;

import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.keywrapping.v1.NativeHkdfKeyWrapperV1Impl;
import io.github.runsecure.hkdfguard.keywrapping.v1.NativeLibraryNotFoundException;
import io.github.runsecure.hkdfguard.testsupport.PrivateTempFiles;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;

/**
 * Which provisioned service the native integration tests run against. Every platform's library
 * refuses to create a KEK during wrap/unwrap - one must be provisioned beforehand - so these tests
 * run only against a provisioned service and are reported as skipped otherwise. Once a service is
 * chosen, a missing or failing library is a test failure, never a silent pass.
 *
 * <p>Test code only: it lives in hkdfguard-test-support, which is never published, and is shared by
 * the native tests of hkdfguard-keywrapping-v1 (which compiles this source into its own tests),
 * hkdfguard-dataencryptionkey and hkdfguard-cache. It is in the key wrapper's interop package so
 * it can use that package's package-private loaders without making them public.
 */
public final class NativeTestEnvironment {
    /**
     * Names a service already provisioned on this machine; its KEK is used, never created or
     * deleted. Always wins over {@link #DEFAULT_SERVICE_NAME}, and is never skipped: setting it
     * means the native tests must run.
     */
    public static final String SERVICE_VARIABLE = "HKDFGUARD_TEST_SERVICE";

    /**
     * The test KEK every platform's provisioning script provisions: scripts/provision-windows-test-key.ps1
     * and scripts/provision-linux-test-key.sh (in this repository), and the other ports'
     * scripts/provision-macos-test-key.sh.
     * Used when {@link #SERVICE_VARIABLE} is unset and the platform can confirm it is provisioned:
     * on Windows the installed library reports it exists, on macOS the installed
     * hkdfguard reports it present. Linux has no non-prompting way to ask whether a
     * KEK exists, so there it is only used when named in {@link #SERVICE_VARIABLE}.
     */
    public static final String DEFAULT_SERVICE_NAME = "com.hkdfguard.integration.test.221";

    /** Optional second provisioned service, for the cross-service isolation test. */
    public static final String OTHER_SERVICE_VARIABLE = "HKDFGUARD_TEST_SERVICE_OTHER";

    /** A valid service name (ASCII letters, digits, '.') that is never provisioned. */
    public static final String UNPROVISIONED_SERVICE_NAME = "hkdfguard.integrationtest.unprovisioned";

    /** The Linux policy file; its tpm.require_pinned_names allowlist is what some Linux tests need. */
    public static final String LINUX_POLICY_PATH = "/etc/hkdfguard/policy.toml";

    /** The Linux provisioning tool, from the hkdfguard package. */
    public static final String LINUX_CLI = "/usr/bin/hkdfguard";

    /** The macOS provisioning tool's file name, installed beside libhkdfguard.dylib. */
    public static final String MACOS_PROVISIONING_TOOL = "hkdfguard";

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
                LINUX_POLICY_PATH + " does not set tpm.require_pinned_names = true (scripts/provision-linux-test-key.sh does).");
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
     * The hkdfguard installed beside the library MacOsNativeLibraryLoader would
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
        var output = PrivateTempFiles.createFile("hkdfguard-tool-", ".out");
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
     * How the macOS default test service resolves: the installed hkdfguard, which
     * created the KEK and so is on its keychain item's access list, is asked whether it is present -
     * asking the library from this process could prompt. "kek: absent" skips; "kek: present", or
     * any failure to ask, runs the tests, so a real failure is reported (and the first native call
     * under it is then made by {@link #awaitNativeAccess}, with a deadline).
     */
    static Resolution macOsResolution() {
        if (macOsInstalledPath() == null)
            return new Resolution(null, "The native KMS library is not installed at " + MacOsNativeLibraryLoader.systemPath() + " or ~/"
                    + MacOsNativeLibraryLoader.USER_DIRECTORY_UNDER_HOME + ".");

        var tool = macOsProvisioningTool();
        if (tool == null)
            return new Resolution(DEFAULT_SERVICE_NAME, "");

        ToolRun run;
        try {
            run = runTool(tool, "status", "--service-name", DEFAULT_SERVICE_NAME);
        } catch (IOException | RuntimeException e) {
            return new Resolution(DEFAULT_SERVICE_NAME, "");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new Resolution(DEFAULT_SERVICE_NAME, "");
        }
        if (run.exitCode() == 0 && run.output().contains("kek: absent"))
            return new Resolution(null, "The test KEK '" + DEFAULT_SERVICE_NAME + "' is not provisioned. Run " + MACOS_PROVISIONING_TOOL
                    + " provision --service-name " + DEFAULT_SERVICE_NAME + ", or set " + SERVICE_VARIABLE + " to a provisioned service.");
        return new Resolution(DEFAULT_SERVICE_NAME, "");
    }

    /**
     * The provisioned service, skipping the calling test when there is none. On macOS the first
     * call also makes the first native call under it, with a deadline (see {@link #awaitNativeAccess}).
     */
    public static String assumeService() {
        var resolution = resolve();
        Assumptions.assumeTrue(resolution.service() != null, resolution.skipReason());
        awaitNativeAccess(resolution.service());
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
            return macOsResolution();

        if (!isWindows())
            return new Resolution(null, "Set " + SERVICE_VARIABLE + " to a service provisioned with hkdfguard provision to run native integration tests. On a Linux TPM host, "
                    + "sudo scripts/provision-linux-test-key.sh provisions " + DEFAULT_SERVICE_NAME + ".");

        if (!windowsLibraryInstalled())
            return new Resolution(null, "The native KMS library is not installed at " + WindowsNativeLibraryLoader.installedPath() + ".");

        int[] answer;
        try {
            answer = queryKekExists(DEFAULT_SERVICE_NAME);
        } catch (RuntimeException e) {
            // Installed, but it couldn't even be asked (it failed verification, say): run the
            // tests so that failure is reported.
            return new Resolution(DEFAULT_SERVICE_NAME, "");
        }

        var status = answer[0];
        var exists = answer[1] != 0;
        if (status == 0 && exists)
            return new Resolution(DEFAULT_SERVICE_NAME, "");
        if (status == 0 || status == AbstractHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND)
            return new Resolution(null, "The test KEK '" + DEFAULT_SERVICE_NAME + "' is not provisioned. Run scripts/provision-windows-test-key.ps1 from an elevated PowerShell, or set "
                    + SERVICE_VARIABLE + " to a provisioned service.");
        if (status == AbstractHkdfGuardKmsLibrary.ERR_KEK_ACCESS_DENIED)
            return new Resolution(null, "The test KEK '" + DEFAULT_SERVICE_NAME
                    + "' exists, but this account may not use it. Add it to the HkdfGuardUsers group (then sign out and in), or run the tests elevated.");
        return new Resolution(DEFAULT_SERVICE_NAME, "");
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

    // --- macOS: a keychain dialog nobody answers ---------------------------------------------------

    /**
     * How long the first native call that could raise a macOS keychain dialog may take before the
     * test fails - the Go port's nativeCallTimeout.
     */
    public static final Duration NATIVE_CALL_TIMEOUT = Duration.ofSeconds(60);

    private static boolean nativeAccessAwaited;
    private static String nativeAccessFailure;

    /**
     * On macOS, makes the first native call under a provisioned service with a deadline, once per
     * test JVM - the Go port's awaitNativeAccess. In the library's legacy keychain mode the KEK's
     * access list names the binary that created it (the provisioning tool), so the first call from
     * any other process - this test JVM - is answered with a keychain dialog in a logged-in session,
     * or with KEK_ACCESS_DENIED (-18) in a session without one. A dialog nobody answers would hang
     * the run; this fails the calling test instead, saying what to do. What the call answers is left
     * to each test. Does nothing on other platforms.
     */
    // This module is test code that lives in src/main only so other modules' tests can share it:
    // failing the calling test is this helper's purpose (S5960 assumes production code).
    @SuppressWarnings("java:S5960")
    public static void awaitNativeAccess(String service) {
        if (!isMacOs())
            return;
        String failure;
        synchronized (NativeTestEnvironment.class) {
            if (!nativeAccessAwaited) {
                nativeAccessAwaited = true;
                nativeAccessFailure = firstNativeCallFailure(service);
            }
            failure = nativeAccessFailure;
        }
        if (failure != null)
            Assertions.fail(failure);
    }

    private static String firstNativeCallFailure(String service) {
        try {
            if (completesWithin(NATIVE_CALL_TIMEOUT, () -> new NativeHkdfKeyWrapperV1Impl(service).generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]).join()))
                return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return "Interrupted while waiting for the first native call under service '" + service + "'.";
        }
        return keychainDialogMessage("The first native call under service '" + service + "'");
    }

    /**
     * Runs a native call that could raise a macOS keychain dialog with {@link #NATIVE_CALL_TIMEOUT},
     * failing the calling test - rather than hanging it - when the call has not returned by then.
     * Whatever the call throws is rethrown.
     *
     * @param what names the call in the failure message
     * @param call the native call
     * @param <T> what the call returns
     * @return what the call returned
     * @throws Exception whatever the call threw
     */
    public static <T> T callWithKeychainTimeout(String what, Callable<T> call) throws Exception {
        var outcome = new AtomicReference<T>();
        var thrown = new AtomicReference<Exception>();
        var returned = completesWithin(NATIVE_CALL_TIMEOUT, () -> {
            try {
                outcome.set(call.call());
            } catch (Exception e) {
                thrown.set(e);
            }
        });
        if (!returned)
            Assertions.fail(keychainDialogMessage(what));
        if (thrown.get() != null)
            throw thrown.get();
        return outcome.get();
    }

    static String keychainDialogMessage(String what) {
        return what + " has not returned after " + NATIVE_CALL_TIMEOUT.toSeconds() + " seconds. On macOS the KEK's keychain item is asking for access in a dialog: "
                + "click \"Always Allow\" (each new test binary asks once). In a session with no UI the library reports KEK_ACCESS_DENIED (-18) "
                + "instead; run the tests from a logged-in session.";
    }

    /**
     * Runs a call on a daemon thread - one left blocked on a dialog never keeps the JVM alive - and
     * reports whether it returned, normally or not, within the timeout.
     */
    static boolean completesWithin(Duration timeout, Runnable call) throws InterruptedException {
        var thread = Thread.ofPlatform().daemon().name("hkdfguard-native-call").unstarted(() -> {
            try {
                call.run();
            } catch (RuntimeException e) {
                // What the call answers is left to the caller; only whether it returned matters here.
            }
        });
        thread.start();
        return thread.join(timeout);
    }

    // --- Directories for key files -----------------------------------------------------------------

    /** On Linux, a private directory for key files is preferably made under the directory this names. */
    public static final String RUNTIME_DIRECTORY_VARIABLE = "XDG_RUNTIME_DIR";

    /** On Linux, where under the home directory private directories for key files are made otherwise. */
    public static final String HOME_TEST_DIRECTORY = ".cache/hkdfguard-tests";

    private static final String OWNER_ONLY = "rwx------";

    /**
     * A new, empty directory for key files the native library reads (hkdfguard_open_file,
     * readKeyFileAsync) or the hkdfguard CLI writes. Delete it with {@link #deleteRecursively}.
     * <ul>
     * <li>Windows: a temporary folder by its real, long path. hkdfguard_open_file refuses an 8.3
     * short name or a link anywhere in a path, and Windows can hand out the temp folder in short form
     * (for example C:\Users\RUNNER~1\... on GitHub-hosted runners); toRealPath expands every short
     * component and resolves any link.</li>
     * <li>Linux: the native library refuses (HKDFGUARD_ERR_FILE_UNTRUSTED, -39) a key file below
     * any group- or world-writable directory, sticky or not - so never under /tmp, /var/tmp or
     * /dev/shm, where java.io.tmpdir and JUnit's TempDir point. A 0700 directory under
     * $XDG_RUNTIME_DIR when that is trusted, else under ~/.cache/hkdfguard-tests; the calling test is
     * skipped, saying why, when neither is (see {@link #linuxPrivateDirectory}).</li>
     * <li>macOS: a temporary folder only this account can use (rwx------), by its real path.</li>
     * </ul>
     *
     * @param prefix the start of the new directory's name
     * @return the new directory, by its real path
     * @throws IOException if it can't be made
     */
    public static Path createTempDirectory(String prefix) throws IOException {
        if (isLinux())
            return linuxPrivateDirectory(prefix, System.getenv(RUNTIME_DIRECTORY_VARIABLE), System.getenv("HOME"), linuxEffectiveUserId());
        return PrivateTempFiles.createDirectory(prefix).toRealPath();
    }

    /**
     * A new 0700 directory, by its real path, with no directory from it up to / that the Linux
     * native library would distrust ({@link #linuxUntrustedReason}): under {@code runtimeDirectory}
     * if that qualifies, else under {@code home}/.cache/hkdfguard-tests (made 0700 as needed). Skips
     * the calling test - an aborted assumption, never a pass - when neither does.
     */
    static Path linuxPrivateDirectory(String prefix, String runtimeDirectory, String home, long uid) {
        var refusals = new ArrayList<String>();

        if (runtimeDirectory == null || runtimeDirectory.isEmpty()) {
            refusals.add("$" + RUNTIME_DIRECTORY_VARIABLE + " is not set");
        } else {
            var created = privateDirectoryUnder(Path.of(runtimeDirectory), false, prefix, uid, refusals);
            if (created != null)
                return created;
        }

        if (home == null || home.isEmpty()) {
            refusals.add("$HOME is not set");
        } else {
            var created = privateDirectoryUnder(Path.of(home).resolve(HOME_TEST_DIRECTORY), true, prefix, uid, refusals);
            if (created != null)
                return created;
        }

        return Assumptions.abort("No private directory for key files: the Linux native library refuses a key file below any group- or world-writable "
                + "directory (sticky or not, so never /tmp, /var/tmp or /dev/shm), and " + String.join("; ", refusals) + ".");
    }

    private static Path privateDirectoryUnder(Path root, boolean createRoot, String prefix, long uid, List<String> refusals) {
        try {
            if (!root.isAbsolute()) {
                refusals.add(root + " is not an absolute path");
                return null;
            }
            if (createRoot && !Files.isDirectory(root)) {
                // Nothing is created below a directory that is already untrusted.
                var existing = root.getParent();
                while (existing != null && !Files.exists(existing))
                    existing = existing.getParent();
                var above = existing == null ? null : linuxUntrustedReason(existing, uid);
                if (above != null) {
                    refusals.add(above);
                    return null;
                }
                Files.createDirectories(root, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(OWNER_ONLY)));
            }
            var reason = linuxUntrustedReason(root, uid);
            if (reason != null) {
                refusals.add(reason);
                return null;
            }
            var directory = Files.createTempDirectory(root.toRealPath(), prefix).toRealPath();
            Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString(OWNER_ONLY));
            reason = linuxUntrustedReason(directory, uid);
            if (reason != null) {
                deleteRecursively(directory);
                refusals.add(reason);
                return null;
            }
            return directory;
        } catch (IOException | UncheckedIOException | SecurityException | UnsupportedOperationException e) {
            refusals.add(root + " is unusable (" + e + ")");
            return null;
        }
    }

    /**
     * Why the Linux native library would refuse a key file in {@code directory}, or null if it
     * wouldn't: the first directory, from {@code directory}'s real path up to /, that is owned by
     * neither root nor {@code uid}, or is writable by group or others. The sticky bit excuses
     * nothing.
     */
    static String linuxUntrustedReason(Path directory, long uid) throws IOException {
        for (var path = directory.toRealPath(); path != null; path = path.getParent()) {
            var owner = ((Number) Files.getAttribute(path, "unix:uid")).longValue();
            var mode = ((Number) Files.getAttribute(path, "unix:mode")).intValue();
            if (owner != 0 && owner != uid)
                return path + " is owned by uid " + owner + ", neither root nor this user (uid " + uid + ")";
            if ((mode & 0_022) != 0) // octal: S_IWGRP | S_IWOTH
                return path + " is writable by group or others (mode " + Integer.toOctalString(mode & 0_7777) + ")";
        }
        return null;
    }

    /** This process's effective user id, from /proc/self/status (Linux only). */
    static long linuxEffectiveUserId() throws IOException {
        for (var line : Files.readAllLines(Path.of("/proc/self/status"))) {
            if (line.startsWith("Uid:"))
                return Long.parseLong(line.substring(4).trim().split("\\s+")[1]);
        }
        throw new IOException("/proc/self/status has no Uid line.");
    }

    /**
     * Deletes a directory made by {@link #createTempDirectory} and everything in it; one that is
     * already gone, or null, is fine.
     *
     * @param directory the directory
     * @throws IOException if something in it can't be deleted
     */
    public static void deleteRecursively(Path directory) throws IOException {
        if (directory == null || !Files.exists(directory, LinkOption.NOFOLLOW_LINKS))
            return;
        try (var paths = Files.walk(directory)) {
            for (var path : paths.sorted(Comparator.reverseOrder()).toList())
                Files.deleteIfExists(path);
        }
    }

    private static String read(String variable) {
        var value = System.getenv(variable);
        return value == null || value.isEmpty() ? null : value;
    }
}
