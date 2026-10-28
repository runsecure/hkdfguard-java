/**
 * Wraps and reveals DEKs under an RSA key in Azure Key Vault, signing every wrapped DEK with a
 * second, EC P-256 key, through the Azure SDK for Java's cryptography clients. Key files are read
 * through {@code hkdfguard-securefile}, so grant that module native access with the JVM option
 * {@code --enable-native-access=io.github.runsecure.hkdfguard.securefile}.
 */
module io.github.runsecure.hkdfguard.keywrapping.azurekeyvault {
    requires transitive io.github.runsecure.hkdfguard.abstractions;
    requires transitive io.github.runsecure.hkdfguard.securefile;
    requires transitive com.azure.security.keyvault.keys;
    requires reactor.core;

    exports io.github.runsecure.hkdfguard.keywrapping.azurekeyvault;
}
