/**
 * A HashiCorp Vault client: {@link io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultClient},
 * a port of vault-client-go whose typed methods are generated from Vault's OpenAPI spec, holding
 * tokens only protected by a data protector on a key ring. Its models are in
 * {@code io.github.runsecure.hkdfguard.integration.hashicorpvault.schema}.
 * <p>
 * Also what every HkdfGuard caller of Vault shares: the token types
 * ({@link io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultTokenProvider},
 * {@link io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultTokenSource}), the errors
 * ({@link io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultRequestException}) and the
 * HTTP rules ({@link io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultHttp}) the
 * HashiCorp Vault secret cache and transit key wrapper are built on.
 */
module io.github.runsecure.hkdfguard.integration.hashicorpvault {
    requires transitive io.github.runsecure.hkdfguard.abstractions;
    requires io.github.runsecure.hkdfguard.remote;
    requires transitive java.net.http;

    exports io.github.runsecure.hkdfguard.integration.hashicorpvault;
    exports io.github.runsecure.hkdfguard.integration.hashicorpvault.schema;
}
