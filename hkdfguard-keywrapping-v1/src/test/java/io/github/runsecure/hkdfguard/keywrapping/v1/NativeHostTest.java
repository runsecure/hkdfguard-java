package io.github.runsecure.hkdfguard.keywrapping.v1;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.keywrapping.v1.interop.LinuxHkdfGuardKmsLibrary;
import io.github.runsecure.hkdfguard.keywrapping.v1.interop.MacOsHkdfGuardKmsLibrary;
import io.github.runsecure.hkdfguard.keywrapping.v1.interop.WindowsHkdfGuardKmsLibrary;
import org.junit.jupiter.api.Test;

class NativeHostTest {
    @Test
    void library_IsTheSameInstanceAcrossCalls() {
        var first = NativeHost.library();

        assertNotNull(first);
        assertSame(first, NativeHost.library());
    }

    @Test
    void library_MatchesThisPlatform() {
        var library = NativeHost.library();

        switch (OsPlatform.current()) {
            case WINDOWS -> assertInstanceOf(WindowsHkdfGuardKmsLibrary.class, library);
            case LINUX -> assertInstanceOf(LinuxHkdfGuardKmsLibrary.class, library);
            case MAC_OS -> assertInstanceOf(MacOsHkdfGuardKmsLibrary.class, library);
        }
    }

    @Test
    void resolve_ReturnsEachPlatformsBinding() {
        assertInstanceOf(WindowsHkdfGuardKmsLibrary.class, NativeHost.resolve(OsPlatform.WINDOWS, "Windows"));
        assertInstanceOf(LinuxHkdfGuardKmsLibrary.class, NativeHost.resolve(OsPlatform.LINUX, "Linux"));
        assertInstanceOf(MacOsHkdfGuardKmsLibrary.class, NativeHost.resolve(OsPlatform.MAC_OS, "macOS"));
    }

    @Test
    void resolve_OnAnUnsupportedPlatform_ThrowsNamingIt() {
        var exception = assertThrows(UnsupportedOperationException.class, () -> NativeHost.resolve(null, "FreeBSD 14"));

        assertTrue(exception.getMessage().contains("FreeBSD 14"));
    }
}
