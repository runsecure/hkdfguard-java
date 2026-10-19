package io.github.runsecure.hkdfguard.keywrapping.v1;

import io.github.runsecure.hkdfguard.keywrapping.v1.interop.AbstractHkdfGuardKmsLibrary;

/**
 * Makes {@link NativeProcessHardening#apply(ProcessHardeningOption...)} stricter. With none, it
 * hardens as far as this process allows; on macOS a weak code signature is only logged.
 */
public enum ProcessHardeningOption {
    /**
     * Fail unless no other process of the same user can attach a debugger to, or inject code into,
     * this process - what the native command-line tools themselves require. On Windows it also
     * closes everything the process creates afterwards (threads, child processes, named pipes and
     * other named objects) to its own user, so use it in a service that shares no objects with
     * other processes by name. On macOS it fails unless the host executable is signed with the
     * Hardened Runtime and without the get-task-allow or DYLD_* entitlements, so an unsigned host,
     * or a JDK launcher whose entitlements allow either, can't use it (check with
     * {@code codesign -d --entitlements - <executable>}). On Linux it adds nothing: the plain call
     * already guarantees it.
     */
    REQUIRE_PROTECTED_SIGNATURE(AbstractHkdfGuardKmsLibrary.HARDEN_REQUIRE_PROTECTED_SIGNATURE);

    private final int nativeFlag;

    ProcessHardeningOption(int nativeFlag) {
        this.nativeFlag = nativeFlag;
    }

    /** The HKDFGUARD_HARDEN_* bit this option sets. */
    int nativeFlag() {
        return nativeFlag;
    }
}
