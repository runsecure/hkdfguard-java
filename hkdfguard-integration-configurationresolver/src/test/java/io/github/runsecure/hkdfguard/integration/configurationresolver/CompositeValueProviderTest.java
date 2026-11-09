package io.github.runsecure.hkdfguard.integration.configurationresolver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** Port of .NET's CompositeValueProviderTests. */
class CompositeValueProviderTest {
    private final SpyValueProvider high = new SpyValueProvider(Map.of("Shared", "high", "HighOnly", "h"));
    private final SpyValueProvider low = new SpyValueProvider(Map.of("Shared", "low", "LowOnly", "lö"));

    @Test
    void findValueReturnsTheValueFromTheFirstProviderThatHasTheKey() {
        var provider = new CompositeValueProvider(high, low);

        assertEquals(Optional.of("high"), provider.findValue("Shared"));
        assertEquals(Optional.of("lö"), provider.findValue("LowOnly"));
        assertEquals(Optional.empty(), provider.findValue("Missing"));

        assertEquals(List.of("Shared", "LowOnly", "Missing"), high.findValueCalls);
        assertEquals(List.of("LowOnly", "Missing"), low.findValueCalls);
    }

    @Test
    void tryGetCharsWritesTheValueFromTheFirstProviderThatHasTheKey() {
        var provider = new CompositeValueProvider(high, low);

        var shared = CharBuffer.allocate(8);
        assertEquals(ValueStatus.FOUND, provider.tryGetChars("Shared", shared));
        assertEquals("high", shared.flip().toString());

        var lowOnly = CharBuffer.allocate(8);
        assertEquals(ValueStatus.FOUND, provider.tryGetChars("LowOnly", lowOnly));
        assertEquals("lö", lowOnly.flip().toString());

        var missing = CharBuffer.allocate(8);
        assertEquals(ValueStatus.NOT_FOUND, provider.tryGetChars("Missing", missing));
        assertEquals(0, missing.position());
        assertEquals(List.of("LowOnly", "Missing"), low.tryGetCharsCalls);
    }

    @Test
    void tryGetBytesWritesTheValueFromTheFirstProviderThatHasTheKey() {
        var provider = new CompositeValueProvider(high, low);

        var shared = ByteBuffer.allocate(8);
        assertEquals(ValueStatus.FOUND, provider.tryGetBytes("Shared", shared));
        assertEquals("high", StandardCharsets.UTF_8.decode(shared.flip()).toString());

        var lowOnly = ByteBuffer.allocate(8);
        assertEquals(ValueStatus.FOUND, provider.tryGetBytes("LowOnly", lowOnly));
        assertEquals("lö", StandardCharsets.UTF_8.decode(lowOnly.flip()).toString());

        var missing = ByteBuffer.allocate(8);
        assertEquals(ValueStatus.NOT_FOUND, provider.tryGetBytes("Missing", missing));
        assertEquals(0, missing.position());
        assertEquals(List.of("LowOnly", "Missing"), low.tryGetBytesCalls);
    }

    @Test
    void destinationTooSmallInTheFirstProviderDoesNotFallThrough() {
        var provider = new CompositeValueProvider(high, low);
        var chars = CharBuffer.allocate(2);
        var bytes = ByteBuffer.allocate(2);

        assertEquals(ValueStatus.DESTINATION_TOO_SMALL, provider.tryGetChars("Shared", chars));
        assertEquals(ValueStatus.DESTINATION_TOO_SMALL, provider.tryGetBytes("Shared", bytes));

        assertEquals(0, chars.position() + bytes.position());
        assertTrue(low.tryGetCharsCalls.isEmpty());
        assertTrue(low.tryGetBytesCalls.isEmpty());
    }

    @Test
    void providerExceptionPropagates() {
        var failing = new SpyValueProvider(Map.of(), new ConfigurationKeyException("Shared", ConfigurationKeyError.VALUE_UNSTABLE));
        var provider = new CompositeValueProvider(failing, low);

        assertThrows(ConfigurationKeyException.class, () -> provider.tryGetChars("Shared", CharBuffer.allocate(8)));
        assertThrows(ConfigurationKeyException.class, () -> provider.tryGetBytes("Shared", ByteBuffer.allocate(8)));
        assertTrue(low.tryGetCharsCalls.isEmpty());
        assertTrue(low.tryGetBytesCalls.isEmpty());
    }

    @Test
    void providersAreInPriorityOrderAndCopied() {
        var list = new ArrayList<ValueProvider>(List.of(high, low));
        var provider = new CompositeValueProvider(list);

        list.clear();

        assertEquals(List.of(high, low), provider.getProviders());
    }

    @Test
    void constructorInvalidProvidersThrows() {
        assertThrows(NullPointerException.class, () -> new CompositeValueProvider((Iterable<ValueProvider>) null));
        assertThrows(NullPointerException.class, () -> new CompositeValueProvider((ValueProvider[]) null));
        assertThrows(IllegalArgumentException.class, () -> new CompositeValueProvider());
        assertThrows(IllegalArgumentException.class, () -> new CompositeValueProvider(high, null));
    }
}
