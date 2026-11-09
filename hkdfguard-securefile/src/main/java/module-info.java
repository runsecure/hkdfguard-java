/**
 * Reads key files only from where no untrusted account could have written or replaced them: the
 * native library's {@code hkdfguard_open_file} rules, checked in Java, for a
 * {@link io.github.runsecure.hkdfguard.abstractions.KeyWrapper#readKeyFileAsync} with no native
 * library to read through - a network KMS's key wrapper, say - and, through
 * {@link io.github.runsecure.hkdfguard.securefile.TrustedFile}, any other file (a secret's, a
 * certificate) to the same rules, with none of a key file's rules about its contents. Grant this module, and
 * io.github.runsecure.hkdfguard.platform, which makes the permission checks' system calls, native
 * access with the JVM option
 * {@code --enable-native-access=io.github.runsecure.hkdfguard.securefile,io.github.runsecure.hkdfguard.platform}.
 */
module io.github.runsecure.hkdfguard.securefile {
    requires transitive io.github.runsecure.hkdfguard.abstractions;
    requires io.github.runsecure.hkdfguard.platform;

    exports io.github.runsecure.hkdfguard.securefile;
}
