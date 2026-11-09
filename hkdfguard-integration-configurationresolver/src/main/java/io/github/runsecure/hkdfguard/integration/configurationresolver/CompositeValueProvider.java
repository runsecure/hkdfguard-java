package io.github.runsecure.hkdfguard.integration.configurationresolver;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Provides configuration values from several value providers, in priority order.
 * <p>
 * Each lookup asks the providers in the order given, and the first provider that has the key supplies
 * the value; the providers after it are not asked. A provider that has the key but whose value does
 * not fit in the destination ends the lookup with {@link ValueStatus#DESTINATION_TOO_SMALL}, rather
 * than falling through to a lower-priority value. An exception thrown by a provider, such as a
 * {@link io.github.runsecure.hkdfguard.integration.configurationresolver.ConfigurationKeyException}, is not
 * caught. Put the provider you trust most first.
 */
public final class CompositeValueProvider implements ValueProvider {
    private final List<ValueProvider> providers;

    /**
     * @param providers the providers to ask, highest priority first
     * @throws NullPointerException     providers is null
     * @throws IllegalArgumentException providers is empty or contains null
     */
    public CompositeValueProvider(ValueProvider... providers) {
        this(Arrays.asList(Objects.requireNonNull(providers, "providers")));
    }

    /**
     * @param providers the providers to ask, highest priority first
     * @throws NullPointerException     providers is null
     * @throws IllegalArgumentException providers is empty or contains null
     */
    public CompositeValueProvider(Iterable<? extends ValueProvider> providers) {
        Objects.requireNonNull(providers, "providers");
        var copy = new ArrayList<ValueProvider>();
        for (var provider : providers) {
            if (provider == null)
                throw new IllegalArgumentException("The value providers cannot contain null.");
            copy.add(provider);
        }
        if (copy.isEmpty())
            throw new IllegalArgumentException("At least one value provider is required.");
        this.providers = Collections.unmodifiableList(copy);
    }

    /**
     * Gets the providers, highest priority first.
     *
     * @return the providers
     */
    public List<ValueProvider> getProviders() {
        return providers;
    }

    @Override
    public Optional<String> findValue(String key) {
        for (var provider : providers) {
            var value = provider.findValue(key);
            if (value.isPresent())
                return value;
        }
        return Optional.empty();
    }

    @Override
    public ValueStatus tryGetChars(String key, CharBuffer destination) {
        for (var provider : providers) {
            var status = provider.tryGetChars(key, destination);
            if (status != ValueStatus.NOT_FOUND)
                return status;
        }
        return ValueStatus.NOT_FOUND;
    }

    @Override
    public ValueStatus tryGetBytes(String key, ByteBuffer destination) {
        for (var provider : providers) {
            var status = provider.tryGetBytes(key, destination);
            if (status != ValueStatus.NOT_FOUND)
                return status;
        }
        return ValueStatus.NOT_FOUND;
    }
}
