/**
 * Wraps and reveals DEKs under a KEK held by the platform's native HkdfGuard KMS library - a TPM
 * or Platform Crypto Provider key on Windows, a Secure Enclave key on macOS, the strongest
 * available provider on Linux - called through the Java FFM API. Grant this module native access
 * with the JVM option {@code --enable-native-access=io.github.runsecure.hkdfguard.keywrapping.v1}.
 */
module io.github.runsecure.hkdfguard.keywrapping.v1 {
    requires transitive io.github.runsecure.hkdfguard.abstractions;
    requires org.bouncycastle.provider;

    exports io.github.runsecure.hkdfguard.keywrapping.v1;
}
