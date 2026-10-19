package io.github.runsecure.hkdfguard.keywrapping.v1;

import static java.lang.foreign.ValueLayout.ADDRESS;
import static java.lang.foreign.ValueLayout.JAVA_INT;
import static java.lang.foreign.ValueLayout.JAVA_LONG;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.keywrapping.v1.interop.AbstractHkdfGuardKmsLibrary;
import io.github.runsecure.hkdfguard.keywrapping.v1.interop.NativeTestEnvironment;
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemoryLayout;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.invoke.MethodHandle;
import java.lang.invoke.VarHandle;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class NativeProcessHardeningTest {
    /**
     * Set to 1 to run the tests that harden this very test process. Afterwards no debugger can
     * attach to the test JVM and it writes no core dump or heap-bearing crash report, so run them in
     * their own JVM (see the README).
     */
    static final String VARIABLE = "HKDFGUARD_TEST_PROCESS_HARDENING";

    @Test
    void apply_Succeeds_WhenTheLibraryReportsOk() {
        var library = new FakeHkdfGuardKmsLibrary();

        NativeProcessHardening.apply(library, 0);

        assertEquals(1, library.hardenCallCount);
    }

    @Test
    void apply_ByDefault_PassesNoFlags() {
        var library = new FakeHkdfGuardKmsLibrary();

        NativeProcessHardening.apply(library, NativeProcessHardening.flagsOf());

        assertEquals(0, library.lastHardenFlags);
    }

    @Test
    void apply_RequireProtectedSignature_PassesTheNativeFlag() {
        var library = new FakeHkdfGuardKmsLibrary();

        NativeProcessHardening.apply(library, NativeProcessHardening.flagsOf(ProcessHardeningOption.REQUIRE_PROTECTED_SIGNATURE));

        assertEquals(AbstractHkdfGuardKmsLibrary.HARDEN_REQUIRE_PROTECTED_SIGNATURE, library.lastHardenFlags);
        assertEquals(0x1, AbstractHkdfGuardKmsLibrary.HARDEN_REQUIRE_PROTECTED_SIGNATURE);
    }

    @Test
    void flagsOf_ARepeatedOption_SetsItsBitOnce() {
        assertEquals(0x1, NativeProcessHardening.flagsOf(ProcessHardeningOption.REQUIRE_PROTECTED_SIGNATURE,
                ProcessHardeningOption.REQUIRE_PROTECTED_SIGNATURE));
    }

    @ParameterizedTest
    @ValueSource(ints = {2, 3, -1, 0x80000000})
    void apply_RefusesAnUnknownFlag_BeforeReachingTheNativeLibrary(int flags) {
        var library = new FakeHkdfGuardKmsLibrary();

        assertThrows(IllegalArgumentException.class, () -> NativeProcessHardening.apply(library, flags));
        assertEquals(0, library.hardenCallCount);
    }

    @Test
    void apply_RefusesNullOptions_BeforeLoadingTheNativeLibrary() {
        assertThrows(NullPointerException.class, () -> NativeProcessHardening.apply((ProcessHardeningOption[]) null));
        assertThrows(NullPointerException.class, () -> NativeProcessHardening.apply((ProcessHardeningOption) null));
        assertThrows(NullPointerException.class,
                () -> NativeProcessHardening.apply(ProcessHardeningOption.REQUIRE_PROTECTED_SIGNATURE, null));
    }

    @Test
    void apply_RefusesANullLibrary() {
        assertThrows(NullPointerException.class, () -> NativeProcessHardening.apply(null, 0));
    }

    @Test
    void apply_Throws_NamingTheStatusAndItsMeaning() {
        var library = new FakeHkdfGuardKmsLibrary();
        library.hardenStatus = AbstractHkdfGuardKmsLibrary.ERR_PROCESS_HARDENING_FAILED;
        library.describe = status -> status == AbstractHkdfGuardKmsLibrary.ERR_PROCESS_HARDENING_FAILED ? "could not disable core dumps" : null;

        var exception = assertThrows(IllegalStateException.class, () -> NativeProcessHardening.apply(library, 0));

        assertEquals("Native process hardening failed with status -20 (could not disable core dumps).", exception.getMessage());
    }

    @Test
    void apply_Throws_WithJustTheStatus_WhenItsMeaningIsUnknown() {
        var library = new FakeHkdfGuardKmsLibrary();
        library.hardenStatus = -150;

        var exception = assertThrows(IllegalStateException.class, () -> NativeProcessHardening.apply(library, 0));

        assertTrue(exception.getMessage().endsWith("status -150."), exception.getMessage());
    }

    @Test
    void apply_ReportsTheNativeLibrarysOwnRefusalOfAFlag() {
        var library = new FakeHkdfGuardKmsLibrary();
        library.hardenStatus = AbstractHkdfGuardKmsLibrary.ERR_INVALID_ARGUMENT;

        var exception = assertThrows(IllegalStateException.class, () -> NativeProcessHardening.apply(library, 0));

        assertTrue(exception.getMessage().startsWith("Native process hardening failed with status -1 (invalid argument"), exception.getMessage());
    }

    @Test
    void apply_LetsALoadFailurePropagate() {
        var library = new FakeHkdfGuardKmsLibrary();
        library.throwOnCall = new SecurityException("refused");

        assertSame(library.throwOnCall, assertThrows(SecurityException.class, () -> NativeProcessHardening.apply(library, 0)));
    }

    // ---- Opt-in: these harden this very test process. ----

    /**
     * On Linux with the package installed: core dumps off, hard limit included, and the dumpable
     * flag cleared, so no debugger of the same user can attach to the test JVM.
     */
    @Test
    void apply_OnLinux_DisablesCoreDumpsAndClearsTheDumpableFlag() throws Throwable {
        assumeOptedIn();
        NativeTestEnvironment.assumeLinuxLibraryInstalled();

        NativeProcessHardening.apply();

        assertEquals(0, Libc.dumpable());
        var limits = Libc.coreLimits();
        assertEquals(0L, limits[0]); // soft
        assertEquals(0L, limits[1]); // hard
    }

    /**
     * On Windows with the native library installed: the process's access list then grants its own
     * account only query, synchronize and terminate - so even this process, asking without
     * SeDebugPrivilege, can no longer open itself to read its memory, though it can still query it.
     */
    @Test
    void apply_OnWindows_ClosesTheProcessToItsOwnAccount() throws Throwable {
        assumeOptedIn();
        NativeTestEnvironment.assumeWindowsLibraryInstalled();

        NativeProcessHardening.apply();

        var readable = Kernel32.openOwnProcess(Kernel32.PROCESS_VM_READ);
        assertEquals(0L, readable.handle(), "PROCESS_VM_READ was still granted");
        assertEquals(Kernel32.ERROR_ACCESS_DENIED, readable.lastError());

        var queryable = Kernel32.openOwnProcess(Kernel32.PROCESS_QUERY_LIMITED_INFORMATION);
        assertNotEquals(0L, queryable.handle(), "PROCESS_QUERY_LIMITED_INFORMATION was refused, error " + queryable.lastError());

        // Idempotent: hardening an already hardened process succeeds.
        NativeProcessHardening.apply();
    }

    /**
     * The strict form, on Windows: a console process sharing no named objects - this test JVM -
     * can meet REQUIRE_PROTECTED_SIGNATURE, and threads started afterwards are closed too.
     */
    @Test
    void apply_OnWindows_WithRequireProtectedSignature_Succeeds() throws Throwable {
        assumeOptedIn();
        NativeTestEnvironment.assumeWindowsLibraryInstalled();

        NativeProcessHardening.apply(ProcessHardeningOption.REQUIRE_PROTECTED_SIGNATURE);

        var readable = Kernel32.openOwnProcess(Kernel32.PROCESS_VM_READ);
        assertEquals(0L, readable.handle(), "PROCESS_VM_READ was still granted");
        assertEquals(Kernel32.ERROR_ACCESS_DENIED, readable.lastError());

        // The JVM still works afterwards: it can start threads and run them to completion.
        var thread = Thread.ofPlatform().start(() -> { });
        thread.join();
    }

    private static void assumeOptedIn() {
        Assumptions.assumeTrue("1".equals(System.getenv(VARIABLE)), "Hardens the test process itself; set " + VARIABLE + "=1 to run it.");
    }

    /** OpenProcess and CloseHandle, with GetLastError captured right after the call. */
    @SuppressWarnings("restricted") // Test-only native calls; the tests run with --enable-native-access.
    private static final class Kernel32 {
        static final int PROCESS_VM_READ = 0x0010;
        static final int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        static final int ERROR_ACCESS_DENIED = 5;

        private static final Linker LINKER = Linker.nativeLinker();
        private static final SymbolLookup KERNEL32 = SymbolLookup.libraryLookup("kernel32.dll", Arena.global());
        private static final MemoryLayout CAPTURED = Linker.Option.captureStateLayout();
        private static final VarHandle LAST_ERROR = CAPTURED.varHandle(MemoryLayout.PathElement.groupElement("GetLastError"));
        // HANDLE OpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId)
        private static final MethodHandle OPEN_PROCESS = LINKER.downcallHandle(KERNEL32.find("OpenProcess").orElseThrow(),
                FunctionDescriptor.of(ADDRESS, JAVA_INT, JAVA_INT, JAVA_INT), Linker.Option.captureCallState("GetLastError"));
        // BOOL CloseHandle(HANDLE hObject)
        private static final MethodHandle CLOSE_HANDLE = LINKER.downcallHandle(KERNEL32.find("CloseHandle").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, ADDRESS));

        record Opened(long handle, int lastError) {
        }

        /** Opens this process for {@code access}, closing any handle it got: only the outcome is kept. */
        static Opened openOwnProcess(int access) throws Throwable {
            try (var arena = Arena.ofConfined()) {
                var state = arena.allocate(CAPTURED);
                var handle = (MemorySegment) OPEN_PROCESS.invokeExact(state, access, 0, (int) ProcessHandle.current().pid());
                var lastError = (int) LAST_ERROR.get(state, 0L);
                if (handle.address() != 0)
                    assertNotEquals(0, (int) CLOSE_HANDLE.invokeExact(handle));
                return new Opened(handle.address(), lastError);
            }
        }
    }

    /** prctl(PR_GET_DUMPABLE) and getrlimit(RLIMIT_CORE). */
    @SuppressWarnings("restricted") // Test-only native calls; the tests run with --enable-native-access.
    private static final class Libc {
        private static final int PR_GET_DUMPABLE = 3;
        private static final int RLIMIT_CORE = 4;

        private static final Linker LINKER = Linker.nativeLinker();
        // int prctl(int option, ...)
        private static final MethodHandle PRCTL = LINKER.downcallHandle(LINKER.defaultLookup().find("prctl").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, JAVA_INT, JAVA_LONG, JAVA_LONG, JAVA_LONG, JAVA_LONG), Linker.Option.firstVariadicArg(1));
        // int getrlimit(int resource, struct rlimit* rlim) - rlim_t is 64 bits on every supported architecture
        private static final MethodHandle GETRLIMIT = LINKER.downcallHandle(LINKER.defaultLookup().find("getrlimit").orElseThrow(),
                FunctionDescriptor.of(JAVA_INT, JAVA_INT, ADDRESS));

        static int dumpable() throws Throwable {
            return (int) PRCTL.invokeExact(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L);
        }

        /** {soft, hard} */
        static long[] coreLimits() throws Throwable {
            try (var arena = Arena.ofConfined()) {
                var limits = arena.allocate(JAVA_LONG, 2);
                assertEquals(0, (int) GETRLIMIT.invokeExact(RLIMIT_CORE, limits));
                return new long[] {limits.getAtIndex(JAVA_LONG, 0), limits.getAtIndex(JAVA_LONG, 1)};
            }
        }
    }
}
