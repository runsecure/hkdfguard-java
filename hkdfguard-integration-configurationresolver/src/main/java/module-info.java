/**
 * ConfigurationResolver templates resolved from HkdfGuard's protected caches - the Java port of
 * .NET's {@code HkdfGuard.Integration.ConfigurationResolver}, with the parts of ConfigurationResolver
 * it uses ported alongside it: the token, reader and resolver, and the value provider contract.
 * {@link io.github.runsecure.hkdfguard.integration.configurationresolver.ProtectedCacheValueProvider}
 * reads a template's values from any {@code ProtectedReadOnlyCache}, and
 * {@link io.github.runsecure.hkdfguard.integration.configurationresolver.ResolvingProtectedCacheCollection}
 * is a cache collection whose values may be templates, resolved on first lookup and cached encrypted.
 */
module io.github.runsecure.hkdfguard.integration.configurationresolver {
    requires transitive io.github.runsecure.hkdfguard.abstractions;

    exports io.github.runsecure.hkdfguard.integration.configurationresolver;
}
