package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

/**
 * What the Windows loader's revocation pass ({@code Win32.checkRevocation}) decides: the load is
 * refused only when Windows definitively reports a certificate in the signer's chain revoked. Any
 * other result - success, revocation servers unreachable, no revocation information, or any other
 * failure - lets the load continue, so a host with no network still starts. The signature and the
 * pinned signer were already validated by the first pass; this pass only adds revocation.
 * No Windows calls, so it is tested on every platform.
 */
final class WindowsRevocationPolicy {
    /** CERT_E_REVOKED: a certificate was explicitly revoked by its issuer. */
    static final int CERTIFICATE_REVOKED = 0x800B010C;

    private WindowsRevocationPolicy() {
    }

    /** Whether a revocation pass that returned {@code status} refuses the load. */
    static boolean refuses(int status) {
        return status == CERTIFICATE_REVOKED;
    }

    /**
     * Throws if {@code status} refuses loading {@code path}.
     *
     * @throws SecurityException a certificate in the signer's chain has been revoked
     */
    static void verify(String path, int status) {
        if (refuses(status))
            throw new SecurityException("'" + path + "' is signed with a certificate that has been revoked; refusing to load it. Install a current release.");
    }
}
