/**
 * A protected read-only cache over one JSON file holding every secret, already encrypted, as a
 * provisioning pipeline's writeJsonSecrets writes it, read on its first lookup through
 * {@code hkdfguard-securefile}'s TrustedFile, so grant that module, and
 * io.github.runsecure.hkdfguard.platform, native access with the JVM option
 * {@code --enable-native-access=io.github.runsecure.hkdfguard.securefile,io.github.runsecure.hkdfguard.platform}.
 */
module io.github.runsecure.hkdfguard.cache.jsonsecretsfile {
    requires transitive io.github.runsecure.hkdfguard.cache;
    requires transitive io.github.runsecure.hkdfguard.securefile;
    requires io.github.runsecure.hkdfguard.cache.filepersecret;
    requires io.github.runsecure.hkdfguard.remote;

    exports io.github.runsecure.hkdfguard.cache.jsonsecretsfile;
}
