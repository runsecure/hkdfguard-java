/**
 * Reads key files only from where no untrusted account could have written or replaced them: the
 * native library's {@code hkdfguard_open_file} rules, checked in Java, for a
 * {@link io.github.runsecure.hkdfguard.abstractions.KeyWrapper#readKeyFileAsync} with no native
 * library to read through - a network KMS's key wrapper, say. Grant this module native access with
 * the JVM option {@code --enable-native-access=io.github.runsecure.hkdfguard.securefile}.
 */
module io.github.runsecure.hkdfguard.securefile {
    requires transitive io.github.runsecure.hkdfguard.abstractions;

    exports io.github.runsecure.hkdfguard.securefile;
}
