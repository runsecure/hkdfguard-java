package io.github.runsecure.hkdfguard.integration.configurationresolver;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.integration.configurationresolver.TestSources.MapValueProvider;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Port of .NET's ValueProviderBaseScenarioTests, and of ProviderScenarioTests' sizing test with a
 * ValueProviderBase double in place of DictionaryValueProvider.
 */
class ValueProviderBaseTest {
    private static final String LARGE = "x".repeat(600);

    static Stream<String> values() {
        return Stream.of("café", "", LARGE);
    }

    @ParameterizedTest
    @MethodSource("values")
    void bytesSourceIsReadAsStringCharsAndCount(String value) {
        var provider = ScriptedBytesProvider.fixed(value);
        var chars = CharBuffer.allocate(value.length());

        assertEquals(Optional.of(value), provider.findValue("Key"));
        assertEquals(ValueStatus.FOUND, provider.tryGetChars("Key", chars));
        assertEquals(OptionalInt.of(value.length()), provider.findCharCount("Key"));

        assertEquals(value, chars.flip().toString());
    }

    @Test
    void bytesSourceCharDestinationTooSmallReportsItAndWipesTheDestination() {
        var provider = ScriptedBytesProvider.fixed("café");
        var array = new char[3];
        Arrays.fill(array, '#');
        var chars = CharBuffer.wrap(array);

        assertEquals(ValueStatus.DESTINATION_TOO_SMALL, provider.tryGetChars("Key", chars));

        assertEquals(0, chars.position());
        assertArrayEquals(new char[3], array);
    }

    @Test
    void bytesSourceMissingKeyIsNotFoundEverywhere() {
        var provider = ScriptedBytesProvider.missing();
        var chars = CharBuffer.allocate(8);

        assertEquals(Optional.empty(), provider.findValue("Key"));
        assertEquals(ValueStatus.NOT_FOUND, provider.tryGetChars("Key", chars));
        assertEquals(OptionalInt.empty(), provider.findCharCount("Key"));
        assertEquals(0, chars.position());
    }

    @Test
    void bytesSourceRemovedBetweenSizingAndReadingIsNotFound() {
        var provider = new ScriptedBytesProvider(new Integer[] {4}, new String[] {null});

        assertEquals(Optional.empty(), provider.findValue("Key"));
    }

    static Stream<Arguments> changesOfSize() {
        return Stream.of(
                Arguments.of(3, "abcdef"),
                Arguments.of(3, 600),
                Arguments.of(600, 700),
                Arguments.of(600, "abcdef"));
    }

    @ParameterizedTest
    @MethodSource("changesOfSize")
    void bytesSourceThatChangesSizeIsReadAgain(int firstCount, Object secondValue) {
        var second = secondValue instanceof String text ? text : "y".repeat((Integer) secondValue);
        var tooLarge = "z".repeat(firstCount + 1);
        var provider = new ScriptedBytesProvider(
                new Integer[] {firstCount, second.getBytes(StandardCharsets.UTF_8).length},
                new String[] {tooLarge, second});

        assertEquals(Optional.of(second), provider.findValue("Key"));

        assertEquals(2, provider.readCalls);
    }

    @Test
    void bytesSourceThatKeepsGrowingThrows() {
        var provider = new ScriptedBytesProvider(new Integer[] {1, 1, 1}, new String[] {"ab", "ab", "ab"});

        var exception = assertThrows(ConfigurationKeyException.class, () -> provider.findValue("Key"));

        assertEquals("Key", exception.getKey());
        assertEquals(ConfigurationKeyError.VALUE_UNSTABLE, exception.getError());
        assertTrue(exception.getSourceIndex().isEmpty());
        assertEquals("The value for a configuration key could not be resolved (VALUE_UNSTABLE).", exception.getMessage());
        assertEquals(3, provider.readCalls);
    }

    @Test
    void bytesSourceThatKeepsGrowingIsReportedAtItsPositionInTheTemplate() {
        // Resolving characters goes through the base class's retry loop.
        var provider = new ScriptedBytesProvider(new Integer[] {1}, new String[] {"ab", "ab", "ab"});
        var resolver = createResolver(provider, "${Key}");

        var exception = assertThrows(ConfigurationKeyException.class, () -> resolver.resolve("é ${Key}", new char[16]));

        assertReportedAt(exception, 2);
    }

    @Test
    void providerKeyExceptionIsReportedAtItsPositionInTheTemplate() {
        var resolver = createResolver(new ThrowingProvider(null), "${Key}");

        assertReportedAt(assertThrows(ConfigurationKeyException.class, () -> resolver.resolve("é ${Key}", new char[16])), 2);
        assertReportedAt(assertThrows(ConfigurationKeyException.class,
                () -> resolver.resolve("é ${Key}".getBytes(StandardCharsets.UTF_8), new byte[16])), 3);
    }

    @Test
    void providerKeyExceptionWithAPositionIsNotWrapped() {
        var provider = new ThrowingProvider(7);
        var resolver = createResolver(provider, "${Key}");

        assertSame(provider.exception, assertThrows(ConfigurationKeyException.class, () -> resolver.resolve("${Key}", new char[16])));
        assertSame(provider.exception, assertThrows(ConfigurationKeyException.class,
                () -> resolver.resolve("${Key}".getBytes(StandardCharsets.UTF_8), new byte[16])));
    }

    /** From ProviderScenarioTests.Base_SizingMethods_ReportTheRequiredBufferSize. */
    @Test
    void baseSizingMethodsReportTheRequiredBufferSize() {
        var provider = new MapValueProvider(Map.of("Key", "café"));

        assertEquals(OptionalInt.of(4), provider.findCharCount("Key"));
        assertEquals(OptionalInt.of(5), provider.findByteCount("Key"));
        assertEquals(OptionalInt.empty(), provider.findCharCount("Missing"));
        assertEquals(OptionalInt.empty(), provider.findByteCount("Missing"));
    }

    private static ConfigurationItemResolver createResolver(ValueProvider provider, String template) {
        var token = new DefaultToken();
        var reader = new ConfigurationItemReaderImpl(token);
        reader.readKeys(template);
        return new ConfigurationItemResolver(token, reader, provider);
    }

    private static void assertReportedAt(ConfigurationKeyException exception, int sourceIndex) {
        assertEquals("Key", exception.getKey());
        assertEquals(ConfigurationKeyError.VALUE_UNSTABLE, exception.getError());
        assertEquals(OptionalInt.of(sourceIndex), exception.getSourceIndex());
        assertFalse(exception.getMessage().contains("Key"));
        var inner = assertInstanceOf(ConfigurationKeyException.class, exception.getCause());
        assertTrue(inner.getSourceIndex().isEmpty());
    }

    /** A provider that throws the same ConfigurationKeyException for every lookup. */
    private static final class ThrowingProvider implements ValueProvider {
        final ConfigurationKeyException exception;

        ThrowingProvider(Integer sourceIndex) {
            exception = sourceIndex != null
                    ? new ConfigurationKeyException("Key", ConfigurationKeyError.VALUE_UNSTABLE, sourceIndex)
                    : new ConfigurationKeyException("Key", ConfigurationKeyError.VALUE_UNSTABLE);
        }

        @Override
        public Optional<String> findValue(String key) {
            throw exception;
        }

        @Override
        public ValueStatus tryGetChars(String key, CharBuffer destination) {
            throw exception;
        }

        @Override
        public ValueStatus tryGetBytes(String key, ByteBuffer destination) {
            throw exception;
        }
    }

    /** A byte-based provider whose reported sizes and actual contents are scripted per call. */
    private static final class ScriptedBytesProvider extends ValueProviderBase {
        private final Integer[] counts;
        private final String[] reads;
        private int countCalls;
        int readCalls;

        ScriptedBytesProvider(Integer[] counts, String[] reads) {
            this.counts = counts;
            this.reads = reads;
        }

        static ScriptedBytesProvider fixed(String value) {
            var count = value.getBytes(StandardCharsets.UTF_8).length;
            return new ScriptedBytesProvider(new Integer[] {count, count, count, count}, new String[] {value, value, value, value});
        }

        static ScriptedBytesProvider missing() {
            return new ScriptedBytesProvider(new Integer[] {null, null, null}, new String[0]);
        }

        @Override
        public ValueStatus tryGetBytes(String key, ByteBuffer destination) {
            var value = reads[readCalls++];
            if (value == null)
                return ValueStatus.NOT_FOUND;
            var bytes = value.getBytes(StandardCharsets.UTF_8);
            if (bytes.length > destination.remaining())
                return ValueStatus.DESTINATION_TOO_SMALL;
            destination.put(bytes);
            return ValueStatus.FOUND;
        }

        @Override
        protected OptionalInt findByteCount(String key) {
            var count = counts[countCalls++ % counts.length];
            return count == null ? OptionalInt.empty() : OptionalInt.of(count);
        }
    }
}
