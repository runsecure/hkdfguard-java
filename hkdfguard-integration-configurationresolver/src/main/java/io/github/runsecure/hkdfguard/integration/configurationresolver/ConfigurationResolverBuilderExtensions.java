package io.github.runsecure.hkdfguard.integration.configurationresolver;

import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import java.util.Objects;

/** Adds HkdfGuard's protected caches to a ConfigurationResolver builder. */
public final class ConfigurationResolverBuilderExtensions {
    private ConfigurationResolverBuilderExtensions() {
    }

    /**
     * Adds a {@link ProtectedCacheValueProvider} over {@code cache}, after any value provider added
     * already.
     *
     * @param builder the builder
     * @param cache   the cache to read values from
     * @return the builder
     * @throws NullPointerException builder or cache is null
     */
    public static ConfigurationResolverBuilder addProtectedCache(ConfigurationResolverBuilder builder, ProtectedReadOnlyCache cache) {
        Objects.requireNonNull(builder, "builder");
        return builder.addValueProvider(new ProtectedCacheValueProvider(cache));
    }
}
