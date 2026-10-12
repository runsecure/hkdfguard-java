/**
 * An AES-256-GCM {@link io.github.runsecure.hkdfguard.abstractions.CryptoProvider} built on
 * BouncyCastle: revealed keys are refreshed in the background, every key's encryption count is
 * capped below the NIST random-nonce limit, and key access fails closed when the KEK goes away.
 */
module io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256 {
    requires transitive io.github.runsecure.hkdfguard.abstractions;
    requires org.bouncycastle.provider;

    exports io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256;
}
