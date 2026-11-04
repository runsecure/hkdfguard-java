/**
 * A provisioning pipeline's writer over one HashiCorp Vault KV secrets engine:
 * {@link io.github.runsecure.hkdfguard.pipeline.hashicorpvault.HashiCorpVaultSecretPipelineWriterImpl}
 * reads each secret over Vault's HTTP API, through the JDK's {@code java.net.http}, encrypts it at
 * once with a pipeline data protector, and writes one file per secret. The token comes from a
 * {@link io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultTokenSource}, in plaintext,
 * since there is no key ring yet to protect it with, and every request follows the rules every
 * HkdfGuard request to Vault does ({@link io.github.runsecure.hkdfguard.integration.hashicorpvault.VaultHttp}).
 */
module io.github.runsecure.hkdfguard.pipeline.hashicorpvault {
    requires transitive io.github.runsecure.hkdfguard.pipeline;
    requires transitive io.github.runsecure.hkdfguard.integration.hashicorpvault;
    requires transitive java.net.http;
    requires io.github.runsecure.hkdfguard.remote;

    exports io.github.runsecure.hkdfguard.pipeline.hashicorpvault;
}
