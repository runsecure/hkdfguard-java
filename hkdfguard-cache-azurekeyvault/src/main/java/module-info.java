/**
 * A protected read-only cache over one Azure Key Vault's secrets,
 * {@link io.github.runsecure.hkdfguard.cache.azurekeyvault.AzureKeyVaultSecretCacheImpl}: each secret is read
 * on its first lookup through the Azure SDK for Java's SecretClient, taken out of the response before
 * the SDK can make it a String, and cached only as ciphertext.
 */
module io.github.runsecure.hkdfguard.cache.azurekeyvault {
    requires transitive io.github.runsecure.hkdfguard.cache;
    requires transitive com.azure.security.keyvault.secrets;
    requires reactor.core;

    exports io.github.runsecure.hkdfguard.cache.azurekeyvault;
}
