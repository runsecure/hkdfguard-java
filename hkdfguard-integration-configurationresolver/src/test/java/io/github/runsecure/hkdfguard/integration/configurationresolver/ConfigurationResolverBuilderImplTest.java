package io.github.runsecure.hkdfguard.integration.configurationresolver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.integration.configurationresolver.TestSources.MapValueProvider;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Port of .NET's ConfigurationResolverBuilderTests. DictionaryValueProvider is replaced by MapValueProvider. */
class ConfigurationResolverBuilderImplTest {
    private final MapValueProvider high = new MapValueProvider(Map.of("Name", "Grace"));
    private final MapValueProvider low = new MapValueProvider(Map.of("Name", "Ada", "Lang", "${Name}"));

    @Test
    void buildUsesTheReaderAndProvidersInTheOrderAdded() {
        var reader = new ConfigurationItemReaderImpl(new DefaultToken());
        reader.readKeys("${Name} ${Lang}");

        var resolver = new ConfigurationResolverBuilderImpl()
                .withReader(reader)
                .addValueProvider(high)
                .addValueProvider(low)
                .build();

        assertInstanceOf(ConfigurationItemResolver.class, resolver);
        assertEquals("Grace ${Name} $${Name}", resolve(resolver, "${Name} ${Lang} $$${Name}"));
    }

    @Test
    void buildDefaultsToTheDefaultTokenAndOptions() {
        var resolver = (ConfigurationItemResolver) new ConfigurationResolverBuilderImpl()
                .withReader(new ConfigurationItemReaderImpl(new DefaultToken()))
                .addValueProvider(low)
                .build();

        assertFalse(resolver.ignoreUnresolvablePlaceholders());
        assertEquals(1, resolver.maxResolutionDepth());
        assertEquals("${Name}", resolve(resolver, "$${Name}"));
    }

    @Test
    void buildAppliesTheTokenAndOptions() {
        var token = new CustomToken("{{", "}}");
        var reader = new ConfigurationItemReaderImpl(token);
        reader.readKeys("{{Lang}} {{Name}} {{Missing}}");

        var resolver = (ConfigurationItemResolver) new ConfigurationResolverBuilderImpl()
                .withToken(token)
                .withReader(reader)
                .addValueProvider(new MapValueProvider(Map.of("Lang", "{{Name}}", "Name", "Ada")))
                .ignoreUnresolvablePlaceholders()
                .withMaxResolutionDepth(2)
                .build();

        assertTrue(resolver.ignoreUnresolvablePlaceholders());
        assertEquals(2, resolver.maxResolutionDepth());
        assertEquals("Ada {{Missing}} ${Lang}", resolve(resolver, "{{Lang}} {{Missing}} ${Lang}"));
    }

    @Test
    void buildEachCallReturnsANewResolver() {
        var builder = new ConfigurationResolverBuilderImpl()
                .withReader(new ConfigurationItemReaderImpl(new DefaultToken()))
                .addValueProvider(low);

        assertNotSame(builder.build(), builder.build());
    }

    @Test
    void buildWithoutAReaderOrAProviderThrows() {
        assertThrows(IllegalStateException.class, () -> new ConfigurationResolverBuilderImpl().addValueProvider(low).build());
        assertThrows(IllegalStateException.class,
                () -> new ConfigurationResolverBuilderImpl().withReader(new ConfigurationItemReaderImpl(new DefaultToken())).build());
    }

    @Test
    void invalidArgumentsThrow() {
        var builder = new ConfigurationResolverBuilderImpl();

        assertThrows(NullPointerException.class, () -> builder.withToken(null));
        assertThrows(NullPointerException.class, () -> builder.withReader(null));
        assertThrows(NullPointerException.class, () -> builder.addValueProvider(null));
        assertThrows(IllegalArgumentException.class, () -> builder.withMaxResolutionDepth(0));
    }

    private static String resolve(ConfigurationResolver resolver, String source) {
        var destination = new char[256];
        var written = resolver.resolve(source, destination);
        return new String(destination, 0, written);
    }
}
