/**
 * A provisioning pipeline's writer over one Azure Key Vault's secrets,
 * {@link io.github.runsecure.hkdfguard.pipeline.azurekeyvault.AzureKeyVaultSecretPipelineWriterImpl}:
 * each secret is read through the Azure SDK for Java's SecretClient, taken out of the response and
 * encrypted before the SDK can make it a String, and written as one encrypted file.
 */
module io.github.runsecure.hkdfguard.pipeline.azurekeyvault {
    requires transitive io.github.runsecure.hkdfguard.pipeline;
    requires transitive com.azure.security.keyvault.secrets;
    requires reactor.core;
    requires io.github.runsecure.hkdfguard.remote;

    exports io.github.runsecure.hkdfguard.pipeline.azurekeyvault;
}
