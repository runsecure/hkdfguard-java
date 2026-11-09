package io.github.runsecure.hkdfguard.integration.configurationresolver;


/** Builds a {@link ConfigurationResolver} from a token, a reader, and one or more value providers. */
public interface ConfigurationResolverBuilder {
    /**
     * Sets the token that defines the start, end, and escape sequences of a configuration item.
     *
     * @param token the token; use the same token as the reader
     * @return this builder
     */
    ConfigurationResolverBuilder withToken(ConfigurationItemTokenBase token);

    /**
     * Sets the reader whose keys are the only keys the resolver may resolve.
     *
     * @param reader the reader
     * @return this builder
     */
    ConfigurationResolverBuilder withReader(ConfigurationItemReader reader);

    /**
     * Adds a value provider, after any added already. Providers added earlier have higher priority.
     *
     * @param valueProvider the value provider
     * @return this builder
     */
    ConfigurationResolverBuilder addValueProvider(ValueProvider valueProvider);

    /**
     * Sets whether an allowed key that no value provider has is copied unchanged instead of throwing.
     *
     * @param ignore whether to copy unresolvable items unchanged
     * @return this builder
     */
    ConfigurationResolverBuilder ignoreUnresolvablePlaceholders(boolean ignore);

    /**
     * Copies an allowed key that no value provider has unchanged instead of throwing.
     *
     * @return this builder
     */
    default ConfigurationResolverBuilder ignoreUnresolvablePlaceholders() {
        return ignoreUnresolvablePlaceholders(true);
    }

    /**
     * Sets the number of levels of configuration items that are resolved.
     *
     * @param maxResolutionDepth the number of levels; 1 inserts values as they are
     * @return this builder
     */
    ConfigurationResolverBuilder withMaxResolutionDepth(int maxResolutionDepth);

    /**
     * Creates a resolver from the builder's settings.
     *
     * @return a new resolver
     */
    ConfigurationResolver build();
}
