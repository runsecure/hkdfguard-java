package io.github.runsecure.hkdfguard.integration.configurationresolver;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Reads the keys of each source before resolving it, so every key in the source is allowed. */
final class ReadingResolver implements ConfigurationResolver {
    private final ConfigurationItemTokenBase token;
    private final ValueProvider[] valueProviders;
    private final ConfigurationItemReaderImpl reader;
    private boolean ignoreUnresolvablePlaceholders;
    private int maxResolutionDepth = 1;
    private List<String> alsoAllowed = List.of();
    private ConfigurationItemResolver resolver;

    ReadingResolver(ConfigurationItemTokenBase token, ValueProvider... valueProviders) {
        this.token = token;
        this.valueProviders = valueProviders;
        this.reader = new ConfigurationItemReaderImpl(token);
    }

    /** Sets IgnoreUnresolvablePlaceholders; call before the first resolve. */
    ReadingResolver ignoringUnresolvablePlaceholders() {
        this.ignoreUnresolvablePlaceholders = true;
        return this;
    }

    /** Sets MaxResolutionDepth; call before the first resolve. */
    ReadingResolver withMaxResolutionDepth(int depth) {
        this.maxResolutionDepth = depth;
        return this;
    }

    /** Texts whose keys are allowed as well as the source's, such as the keys of items inside values. */
    ReadingResolver alsoAllowing(List<String> texts) {
        this.alsoAllowed = List.copyOf(texts);
        return this;
    }

    @Override
    public int resolve(CharSequence source, CharBuffer destination) {
        readKeys(source.toString());
        return resolver().resolve(source, destination);
    }

    @Override
    public int resolve(ByteBuffer source, ByteBuffer destination) {
        readKeys(StandardCharsets.UTF_8.decode(source.duplicate()).toString());
        return resolver().resolve(source, destination);
    }

    private void readKeys(String source) {
        var texts = new ArrayList<String>();
        texts.add(source);
        texts.addAll(alsoAllowed);
        reader.readKeys(texts);
    }

    private ConfigurationItemResolver resolver() {
        if (resolver == null)
            resolver = new ConfigurationItemResolver(token, reader, valueProviders)
                    .withIgnoreUnresolvablePlaceholders(ignoreUnresolvablePlaceholders)
                    .withMaxResolutionDepth(maxResolutionDepth);
        return resolver;
    }
}
