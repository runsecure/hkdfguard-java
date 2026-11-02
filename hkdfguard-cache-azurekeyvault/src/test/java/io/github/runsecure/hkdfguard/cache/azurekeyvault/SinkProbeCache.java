package io.github.runsecure.hkdfguard.cache.azurekeyvault;

import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.cache.RemoteSecretCache;
import io.github.runsecure.hkdfguard.cache.SecretNameMatching;
import io.github.runsecure.hkdfguard.cache.SecretValueSink;
import java.util.function.BiConsumer;

/**
 * A RemoteSecretCache whose fetch is a test's: the way to get a real {@link SecretValueSink}, whose
 * constructor isn't public, into a request made through {@link SecretCapturePolicy} directly.
 */
final class SinkProbeCache extends RemoteSecretCache {
    private final BiConsumer<String, SecretValueSink> fetch;

    SinkProbeCache(KeyRing keyRing, BiConsumer<String, SecretValueSink> fetch) {
        super(keyRing, SecretNameMatching.IGNORE_ASCII_CASE, null);
        this.fetch = fetch;
    }

    @Override
    protected boolean isValidName(String name) {
        return AzureKeyVaultSecretCacheImpl.isValidSecretName(name);
    }

    @Override
    protected void fetch(String name, SecretValueSink value) {
        fetch.accept(name, value);
    }
}
