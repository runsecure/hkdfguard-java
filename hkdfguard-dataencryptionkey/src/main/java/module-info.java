/**
 * Versioned rings of data encryption keys: {@link io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl}
 * tracks keys by version and rotates ephemeral ones, {@link io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingBuilder}
 * builds a ring from wrapped key files and ephemeral keys, and the
 * {@code enc::v{version}::{base64}} wire format is
 * {@link io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider.DefaultFormatProviderImpl}.
 */
module io.github.runsecure.hkdfguard.dataencryptionkey {
    requires transitive io.github.runsecure.hkdfguard.abstractions;

    exports io.github.runsecure.hkdfguard.dataencryptionkey;
    exports io.github.runsecure.hkdfguard.dataencryptionkey.formatprovider;
    exports io.github.runsecure.hkdfguard.dataencryptionkey.utilities;
}
