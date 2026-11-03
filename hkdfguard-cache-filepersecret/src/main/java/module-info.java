/**
 * A protected read-only cache over a local folder holding one already-encrypted file per secret,
 * each read on its first lookup through {@code hkdfguard-securefile}'s TrustedFile, so grant that
 * module, and io.github.runsecure.hkdfguard.platform, native access with the JVM option
 * {@code --enable-native-access=io.github.runsecure.hkdfguard.securefile,io.github.runsecure.hkdfguard.platform}.
 */
module io.github.runsecure.hkdfguard.cache.filepersecret {
    requires transitive io.github.runsecure.hkdfguard.cache;
    requires transitive io.github.runsecure.hkdfguard.securefile;

    exports io.github.runsecure.hkdfguard.cache.filepersecret;
}
