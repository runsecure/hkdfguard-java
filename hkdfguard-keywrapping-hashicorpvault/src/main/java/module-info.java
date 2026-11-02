/**
 * Wraps and reveals DEKs under one key in a HashiCorp Vault transit secrets engine:
 * {@link io.github.runsecure.hkdfguard.keywrapping.hashicorpvault.HashiCorpVaultTransitKeyWrapperImpl}
 * calls Vault's HTTP API through the JDK's {@code java.net.http}, with the token a
 * {@link io.github.runsecure.hkdfguard.keywrapping.hashicorpvault.VaultTokenSource} supplies. Key
 * files are read through {@code hkdfguard-securefile}, so grant that module native access with the
 * JVM option {@code --enable-native-access=io.github.runsecure.hkdfguard.securefile}.
 */
module io.github.runsecure.hkdfguard.keywrapping.hashicorpvault {
    requires transitive io.github.runsecure.hkdfguard.abstractions;
    requires transitive io.github.runsecure.hkdfguard.securefile;
    requires io.github.runsecure.hkdfguard.remote;
    requires transitive java.net.http;

    exports io.github.runsecure.hkdfguard.keywrapping.hashicorpvault;
}
