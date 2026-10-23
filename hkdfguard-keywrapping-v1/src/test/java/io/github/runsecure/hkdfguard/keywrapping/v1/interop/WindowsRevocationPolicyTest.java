package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

// The decision only - no Windows calls - so it runs on every platform.
class WindowsRevocationPolicyTest {
    private static final String PATH = "C:\\Program Files\\HkdfGuard\\v1\\HkdfGuard.dll";

    @Test
    void aRevokedCertificate_RefusesTheLoad() {
        assertTrue(WindowsRevocationPolicy.refuses(0x800B010C)); // CERT_E_REVOKED

        var ex = assertThrows(SecurityException.class, () -> WindowsRevocationPolicy.verify(PATH, 0x800B010C));
        assertTrue(ex.getMessage().contains(PATH));
        assertTrue(ex.getMessage().contains("revoked"));
    }

    @ParameterizedTest
    @ValueSource(ints = {
            0,           // success: checked, not revoked
            0x80092013,  // CRYPT_E_REVOCATION_OFFLINE: servers unreachable
            0x80092012,  // CRYPT_E_NO_REVOCATION_CHECK: no revocation information
            0x800B010E,  // CERT_E_REVOCATION_FAILURE: status could not be determined
            0x800B0101,  // any other result (CERT_E_EXPIRED here)
    })
    void anyOtherResult_LetsTheLoadContinue(int status) {
        assertFalse(WindowsRevocationPolicy.refuses(status));
        assertDoesNotThrow(() -> WindowsRevocationPolicy.verify(PATH, status));
    }
}
