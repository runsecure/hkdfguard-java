package io.github.runsecure.hkdfguard.abstractions;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class RecordTypesTest {
    @Test
    void keyTrackingValue_HoldsWhatItWasCreatedWith_AndRequiresAValue() {
        var value = new KeyTrackingValue(7, new byte[] {1, 2, 3});

        assertEquals(7, value.keyVersion());
        assertArrayEquals(new byte[] {1, 2, 3}, value.value());
        assertThrows(NullPointerException.class, () -> new KeyTrackingValue(1, null));
    }

    @Test
    void versionedKey_RequiresAKey() {
        assertThrows(NullPointerException.class, () -> new VersionedKey(1, null));
    }

    @Test
    void sharedLimits_MatchTheOtherPorts() {
        assertEquals(3, RefreshFailurePolicy.DEFAULT_MAX_REFRESH_FAILURES);
        assertEquals(512, WrappedKeyLimits.MAX_BYTES);
        assertEquals("HkdfGuard.Cache:", ProtectedCacheBase.AAD_PREFIX);
        assertEquals("HkdfGuard.EncryptedConfiguration", ProtectedConfigurationPurpose.PREFIX);
    }
}
