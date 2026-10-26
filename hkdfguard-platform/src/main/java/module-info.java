/**
 * Internal to HkdfGuard: the operating-system calls and path checks shared by the native library
 * loader ({@code io.github.runsecure.hkdfguard.keywrapping.v1}) and the key-file checks
 * ({@code io.github.runsecure.hkdfguard.securefile}), exported only to them. Grant this module
 * native access with the JVM option {@code --enable-native-access=io.github.runsecure.hkdfguard.platform}.
 */
module io.github.runsecure.hkdfguard.platform {
    exports io.github.runsecure.hkdfguard.platform.unix to
            io.github.runsecure.hkdfguard.keywrapping.v1,
            io.github.runsecure.hkdfguard.securefile;
    exports io.github.runsecure.hkdfguard.platform.windows to
            io.github.runsecure.hkdfguard.keywrapping.v1,
            io.github.runsecure.hkdfguard.securefile;
}
