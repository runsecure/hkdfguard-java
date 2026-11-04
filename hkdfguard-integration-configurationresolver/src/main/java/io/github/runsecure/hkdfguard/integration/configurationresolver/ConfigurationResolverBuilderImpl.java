package io.github.runsecure.hkdfguard.integration.configurationresolver;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Builds a {@link ConfigurationItemResolver} from a token, a reader, and one or more value providers.
 * The counterpart of .NET's {@code ConfigurationResolverBuilder}.
 * <p>
 * The token defaults to {@link DefaultToken}. A reader and at least one value provider are required.
 * The reader is not created for you, because only you can read the keys of your trusted template into
 * it; create it with the same token. Each call to {@link #build()} returns a new resolver that shares
 * the reader and the value providers.
 *
 * <pre>{@code
 * var token = new DefaultToken();
 * var reader = new ConfigurationItemReaderImpl(token);
 * reader.readKeys(template);
 *
 * var resolver = new ConfigurationResolverBuilderImpl()
 *         .withToken(token)
 *         .withReader(reader)
 *         .addValueProvider(new ProtectedCacheValueProvider(secrets))
 *         .build();
 * }</pre>
 */
public class ConfigurationResolverBuilderImpl implements ConfigurationResolverBuilder {
    private final List<ValueProvider> valueProviders = new ArrayList<>();
    private ConfigurationItemTokenBase token = new DefaultToken();
    private ConfigurationItemReader reader;
    private boolean ignoreUnresolvablePlaceholders;
    private int maxResolutionDepth = 1;

    /** An empty builder, with the default token. */
    public ConfigurationResolverBuilderImpl() {
    }

    /**
     * {@inheritDoc}
     *
     * @throws NullPointerException token is null
     */
    @Override
    public ConfigurationResolverBuilder withToken(ConfigurationItemTokenBase token) {
        this.token = Objects.requireNonNull(token, "token");
        return this;
    }

    /**
     * {@inheritDoc}
     *
     * @throws NullPointerException reader is null
     */
    @Override
    public ConfigurationResolverBuilder withReader(ConfigurationItemReader reader) {
        this.reader = Objects.requireNonNull(reader, "reader");
        return this;
    }

    /**
     * {@inheritDoc}
     *
     * @throws NullPointerException valueProvider is null
     */
    @Override
    public ConfigurationResolverBuilder addValueProvider(ValueProvider valueProvider) {
        valueProviders.add(Objects.requireNonNull(valueProvider, "valueProvider"));
        return this;
    }

    @Override
    public ConfigurationResolverBuilder ignoreUnresolvablePlaceholders(boolean ignore) {
        this.ignoreUnresolvablePlaceholders = ignore;
        return this;
    }

    /**
     * {@inheritDoc}
     *
     * @throws IllegalArgumentException maxResolutionDepth is less than 1
     */
    @Override
    public ConfigurationResolverBuilder withMaxResolutionDepth(int maxResolutionDepth) {
        if (maxResolutionDepth < 1)
            throw new IllegalArgumentException("maxResolutionDepth must be at least 1.");
        this.maxResolutionDepth = maxResolutionDepth;
        return this;
    }

    /**
     * {@inheritDoc}
     *
     * @throws IllegalStateException no reader has been set, or no value provider has been added
     */
    @Override
    public ConfigurationResolver build() {
        if (reader == null)
            throw new IllegalStateException("A reader is required. Call withReader before build.");
        if (valueProviders.isEmpty())
            throw new IllegalStateException("At least one value provider is required. Call addValueProvider before build.");

        return new ConfigurationItemResolver(token, reader, List.copyOf(valueProviders))
                .withIgnoreUnresolvablePlaceholders(ignoreUnresolvablePlaceholders)
                .withMaxResolutionDepth(maxResolutionDepth);
    }
}
