package io.github.runsecure.hkdfguard.keywrapping.v1;

import io.github.runsecure.hkdfguard.keywrapping.v1.interop.AbstractHkdfGuardKmsLibrary;
import java.util.Objects;

/**
 * Opt-in hardening of the whole process, through the native KMS library's
 * hkdfguard_harden_process_with_flags. DEKs pass through this process's memory, so a crash dump,
 * or another process of the same user attaching a debugger or reading its memory, could recover
 * them. The native library never does this on its own, and no machine policy turns it on: it
 * changes process-wide state the application owns. What it does:
 * <ul>
 * <li><b>Windows:</b> crash reports leave out the heap (WerSetFlags NOHEAP), and the process's
 * and its existing threads' access lists are replaced so that only SYSTEM may read or write its
 * memory, inject threads or duplicate its handles - the account it runs as keeps only query,
 * synchronize and terminate. Threads started later keep the default access unless
 * {@link ProcessHardeningOption#REQUIRE_PROTECTED_SIGNATURE} is passed; call it early, before
 * starting worker threads.</li>
 * <li><b>Linux:</b> the core dump limit is set to zero (hard limit included) and the process's
 * dumpable flag is cleared, which also stops ptrace and /proc/&lt;pid&gt;/mem access by other
 * processes of the same user.</li>
 * <li><b>macOS:</b> core dumps are disabled and debugger attachment is denied; the host
 * executable's code signature decides whether code injection is possible, which the library can
 * check but not change.</li>
 * </ul>
 * <p>
 * It is opt-in because it is process-wide: debuggers, jcmd, jstack and other attach-based tools,
 * and crash dumps stop working for the application. Call it once, early - first thing in
 * {@code main}, before starting a framework or worker threads - and after any privilege drop (on
 * Linux the kernel resets the dumpable flag when a process's credentials change). It is a
 * same-user barrier: it does not stop administrators, root, SYSTEM, a process with CAP_SYS_PTRACE
 * or SeDebugPrivilege, or the kernel, and it does not keep memory out of swap, the page file or
 * hibernation files; those are host settings.
 */
public final class NativeProcessHardening {
    private NativeProcessHardening() {
    }

    /**
     * Applies the hardening, loading (and verifying) the native KMS library if it isn't already.
     * With {@link ProcessHardeningOption#REQUIRE_PROTECTED_SIGNATURE} it fails unless no other
     * process of the same user can debug or inject into this one.
     *
     * @param options how strict to be; none for the plain hardening
     * @throws NullPointerException           options, or one of them, is null
     * @throws IllegalStateException          the hardening failed, or the process can't meet
     *                                        {@link ProcessHardeningOption#REQUIRE_PROTECTED_SIGNATURE};
     *                                        treat it as a reason not to start
     * @throws NativeLibraryNotFoundException the native KMS library is not installed
     * @throws SecurityException              the installed native library failed verification
     * @throws UnsupportedOperationException  there is no native KMS library for this platform
     */
    public static void apply(ProcessHardeningOption... options) {
        // The options are checked before the native library is loaded.
        var flags = flagsOf(options);
        apply(NativeHost.library(), flags);
    }

    /** The HKDFGUARD_HARDEN_* bits {@code options} set. */
    static int flagsOf(ProcessHardeningOption... options) {
        Objects.requireNonNull(options, "options");
        var flags = 0;
        for (var option : options)
            flags |= Objects.requireNonNull(option, "options contains null").nativeFlag();
        return flags;
    }

    /**
     * The decision, against any binding: calls it with {@code flags} and turns a failure into an
     * exception naming the status and its meaning.
     *
     * @throws IllegalArgumentException flags has a bit this library doesn't define - checked here
     *                                  so it never reaches native code, which would refuse it anyway
     */
    static void apply(AbstractHkdfGuardKmsLibrary library, int flags) {
        Objects.requireNonNull(library, "library");
        if ((flags & ~AbstractHkdfGuardKmsLibrary.HARDEN_REQUIRE_PROTECTED_SIGNATURE) != 0)
            throw new IllegalArgumentException("Unknown process hardening flags: 0x" + Integer.toHexString(flags) + ".");

        var status = library.hardenProcess(flags);
        if (status == AbstractHkdfGuardKmsLibrary.OK)
            return;

        var description = library.describeStatus(status);
        var meaning = description != null ? " (" + description + ")" : "";
        throw new IllegalStateException("Native process hardening failed with status " + status + meaning + ".");
    }
}
