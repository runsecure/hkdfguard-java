package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;

import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
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
    public static final String DEFAULT_WINDOWS_SERVICE_NAME = "com.hkdfguard.native.windows.test";

    /** Optional second provisioned service, for the cross-service isolation test. */
    public static final String OTHER_SERVICE_VARIABLE = "HKDFGUARD_TEST_SERVICE_OTHER";

    /** A valid service name (ASCII letters, digits, '.') that is never provisioned. */
    public static final String UNPROVISIONED_SERVICE_NAME = "hkdfguard.integrationtest.unprovisioned";

    private record Resolution(String service, String skipReason) {
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

        if (!isWindows())
            return new Resolution(null, "Set " + SERVICE_VARIABLE + " to a service provisioned with hkdfguard-v1-initialize to run native integration tests.");

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
        if (status == 0 || status == WindowsHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND)
            return new Resolution(null, "The test KEK '" + DEFAULT_WINDOWS_SERVICE_NAME + "' is not provisioned. Run scripts/provision-windows-test-key.ps1 from an elevated PowerShell, or set "
                    + SERVICE_VARIABLE + " to a provisioned service.");
        if (status == WindowsHkdfGuardKmsLibrary.ERR_ACCESS_DENIED)
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

    private static String read(String variable) {
        var value = System.getenv(variable);
        return value == null || value.isEmpty() ? null : value;
    }
}
