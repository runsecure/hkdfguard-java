/**
 * Wraps and reveals DEKs under one symmetric AWS KMS key, through the AWS SDK for Java 2.x's
 * {@code KmsAsyncClient}, which the application builds, configures and closes. Key files are read
 * through {@code hkdfguard-securefile}, so grant that module native access with the JVM option
 * {@code --enable-native-access=io.github.runsecure.hkdfguard.securefile}.
 */
module io.github.runsecure.hkdfguard.keywrapping.awskms {
    requires transitive io.github.runsecure.hkdfguard.abstractions;
    requires transitive io.github.runsecure.hkdfguard.securefile;
    requires transitive software.amazon.awssdk.services.kms;
    requires software.amazon.awssdk.core;
    requires software.amazon.awssdk.awscore;

    exports io.github.runsecure.hkdfguard.keywrapping.awskms;
}
