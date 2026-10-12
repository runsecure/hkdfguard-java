package io.github.runsecure.hkdfguard.keywrapping.v1.interop;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class KmsLibraryContractTest {
    @Test
    void sharedConstants_MatchTheNativeHeaders() {
        assertEquals(32, AbstractHkdfGuardKmsLibrary.DEK_LENGTH);
        assertEquals(0, AbstractHkdfGuardKmsLibrary.OK);
    }

    @Test
    void windowsErrorConstants_MatchTheNativeHeader() {
        int[] expected = {-1, -2, -3, -4, -5, -6, -7, -8, -9, -10, -11, -12, -13, -14};
        int[] actual = {
                WindowsHkdfGuardKmsLibrary.ERR_INVALID_ARG, WindowsHkdfGuardKmsLibrary.ERR_BUFFER_TOO_SMALL,
                WindowsHkdfGuardKmsLibrary.ERR_PROVIDER, WindowsHkdfGuardKmsLibrary.ERR_CRYPTO,
                WindowsHkdfGuardKmsLibrary.ERR_AUTH_FAILED, WindowsHkdfGuardKmsLibrary.ERR_MALFORMED,
                WindowsHkdfGuardKmsLibrary.ERR_INTERNAL, WindowsHkdfGuardKmsLibrary.ERR_SERVICE_NAME_INVALID,
                WindowsHkdfGuardKmsLibrary.ERR_INVALID_POLICY, WindowsHkdfGuardKmsLibrary.ERR_GROUP_INVALID,
                WindowsHkdfGuardKmsLibrary.ERR_KEK_MISMATCH, WindowsHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND,
                WindowsHkdfGuardKmsLibrary.ERR_ACCESS_DENIED, WindowsHkdfGuardKmsLibrary.ERR_KEK_ACL_INVALID,
        };
        assertEquals(java.util.Arrays.toString(expected), java.util.Arrays.toString(actual));
    }

    @Test
    void windows_DescribesEveryDefinedStatus_AndNothingElse() {
        var library = new WindowsHkdfGuardKmsLibrary();

        for (var status = -14; status <= -1; status++) {
            var description = library.describeStatus(status);
            assertFalse(description == null || description.isEmpty(), "no description for " + status);
        }

        assertNull(library.describeStatus(-15));
        assertNull(library.describeStatus(1));
        assertTrue(library.describeStatus(WindowsHkdfGuardKmsLibrary.ERR_ACCESS_DENIED).contains("not authorized"));
        assertTrue(library.describeStatus(WindowsHkdfGuardKmsLibrary.ERR_ACCESS_DENIED).contains("HkdfGuardUsers"));
        assertTrue(library.describeStatus(WindowsHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND).contains("provision"));
    }

    @Test
    void macOs_DescribesEveryReturnedStatus_ButNotTheReservedOnes() {
        var library = new MacOsHkdfGuardKmsLibrary();

        for (var status : new int[] {-1, -2, -5, -6, -7, -8, -9, -10, -11, -12, -13, -14, -15, -16, -17, -18}) {
            var description = library.describeStatus(status);
            assertFalse(description == null || description.isEmpty(), "no description for " + status);
        }

        assertNull(library.describeStatus(MacOsHkdfGuardKmsLibrary.ERR_KEY_UNAVAILABLE));        // reserved, never returned
        assertNull(library.describeStatus(MacOsHkdfGuardKmsLibrary.ERR_PUBLIC_KEY_UNAVAILABLE)); // reserved, never returned
        assertNull(library.describeStatus(-19));
    }

    @Test
    void linuxErrorConstants_MatchTheNativeHeader_AndHaveNoDescriptions() {
        assertEquals(-1, LinuxHkdfGuardKmsLibrary.ERR_INVALID_ARGUMENT);
        assertEquals(-2, LinuxHkdfGuardKmsLibrary.ERR_BUFFER_TOO_SMALL);
        assertEquals(-3, LinuxHkdfGuardKmsLibrary.ERR_PROVIDER_UNAVAILABLE);
        assertEquals(-4, LinuxHkdfGuardKmsLibrary.ERR_PROVIDER_ERROR);
        assertEquals(-5, LinuxHkdfGuardKmsLibrary.ERR_CRYPTO_ERROR);
        assertEquals(-6, LinuxHkdfGuardKmsLibrary.ERR_INTERNAL_ERROR);
        assertEquals(-7, LinuxHkdfGuardKmsLibrary.ERR_INVALID_UTF8);
        assertEquals(-8, LinuxHkdfGuardKmsLibrary.ERR_MISSING_SERVICE_NAME);
        assertNull(new LinuxHkdfGuardKmsLibrary().describeStatus(-1));
    }

    @Test
    void macOsErrorConstants_MatchTheNativeHeader() {
        assertEquals(-1, MacOsHkdfGuardKmsLibrary.ERR_INVALID_INPUT_LENGTH);
        assertEquals(-2, MacOsHkdfGuardKmsLibrary.ERR_OUTPUT_BUFFER_TOO_SMALL);
        assertEquals(-3, MacOsHkdfGuardKmsLibrary.ERR_KEY_UNAVAILABLE);
        assertEquals(-4, MacOsHkdfGuardKmsLibrary.ERR_PUBLIC_KEY_UNAVAILABLE);
        assertEquals(-5, MacOsHkdfGuardKmsLibrary.ERR_ENCRYPTION_FAILED);
        assertEquals(-6, MacOsHkdfGuardKmsLibrary.ERR_DECRYPTION_FAILED);
        assertEquals(-7, MacOsHkdfGuardKmsLibrary.ERR_UNEXPECTED_OUTPUT_LENGTH);
        assertEquals(-8, MacOsHkdfGuardKmsLibrary.ERR_INVALID_SERVICE_IDENTIFIER);
        assertEquals(-9, MacOsHkdfGuardKmsLibrary.ERR_ENCLAVE_UNAVAILABLE);
        assertEquals(-10, MacOsHkdfGuardKmsLibrary.ERR_KEK_NOT_FOUND);
        assertEquals(-11, MacOsHkdfGuardKmsLibrary.ERR_KEK_CORRUPTED);
        assertEquals(-12, MacOsHkdfGuardKmsLibrary.ERR_ACCESS_CONTROL_CREATION_FAILED);
        assertEquals(-13, MacOsHkdfGuardKmsLibrary.ERR_KEY_GENERATION_FAILED);
        assertEquals(-14, MacOsHkdfGuardKmsLibrary.ERR_KEYCHAIN_WRITE_FAILED);
        assertEquals(-15, MacOsHkdfGuardKmsLibrary.ERR_KEK_VERIFICATION_FAILED);
        assertEquals(-16, MacOsHkdfGuardKmsLibrary.ERR_FINGERPRINT_MISMATCH);
        assertEquals(-17, MacOsHkdfGuardKmsLibrary.ERR_KEYCHAIN_ACCESS_DENIED);
        assertEquals(-18, MacOsHkdfGuardKmsLibrary.ERR_KEYCHAIN_READ_FAILED);
    }
}
