package io.github.runsecure.hkdfguard.integration.configurationresolver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** Port of .NET's ReaderAndTokenScenarioTests: the reader and the token. */
class ConfigurationItemReaderImplTest {
    private static final String TEXT = "this is my ${ value 1 }, and this is ${value2} and lastly this is ${value3}";

    private final ConfigurationItemReaderImpl reader = new ConfigurationItemReaderImpl(new DefaultToken());

    @Test
    void readKeysFromCharsBytesAndStreamReturnTheSameKeys() {
        var expected = List.of("value 1", "value2", "value3");
        var bytes = TEXT.getBytes(StandardCharsets.UTF_8);

        assertEquals(expected, reader.readKeys(TEXT));
        assertEquals(expected, reader.readKeys(bytes));
        assertEquals(expected, reader.readKeys(ByteBuffer.wrap(bytes)));
        assertEquals(expected, reader.readKeys(new ByteArrayInputStream(bytes)));
    }

    @Test
    void readKeysStreamWithExplicitEncodingDecodesWithIt() {
        var stream = new ByteArrayInputStream("${ café }".getBytes(StandardCharsets.ISO_8859_1));

        assertEquals(List.of("café"), reader.readKeys(stream, StandardCharsets.ISO_8859_1));
    }

    @Test
    void readKeysStreamIsReadFromItsPositionAndLeftOpen() {
        var stream = new ByteArrayInputStream("${skipped} ${read}".getBytes(StandardCharsets.UTF_8));
        assertEquals("${skipped} ".length(), stream.skip("${skipped} ".length()));

        assertEquals(List.of("read"), reader.readKeys(stream));
        assertEquals(-1, stream.read());
    }

    @Test
    void readKeysByteBufferIsReadFromItsPositionWhichIsNotChanged() {
        // Java only: a ByteBuffer is read from its position to its limit.
        var buffer = ByteBuffer.wrap("${skipped} ${read} ${cut}".getBytes(StandardCharsets.UTF_8));
        buffer.position("${skipped} ".length()).limit("${skipped} ${read}".length());

        assertEquals(List.of("read"), reader.readKeys(buffer));
        assertEquals("${skipped} ".length(), buffer.position());
    }

    static Stream<Arguments> skippedItems() {
        return Stream.of(
                Arguments.of("", List.of()),
                Arguments.of("no items", List.of()),
                Arguments.of("${} ${ } ${a}", List.of("a")),
                Arguments.of("${a} ${unterminated", List.of("a")),
                Arguments.of("${a}${b}", List.of("a", "b")),
                Arguments.of("$${a} ${b} $${", List.of("b")),
                Arguments.of("$$${a} $${b ${c}}", List.of("c")));
    }

    @ParameterizedTest
    @MethodSource("skippedItems")
    void readKeysSkipsEmptyUnterminatedAndEscapedItems(String text, List<String> expected) {
        assertEquals(expected, reader.readKeys(text));
    }

    @Test
    void keysReturnsTheMostRecentRead() {
        assertTrue(reader.keys().isEmpty());

        reader.readKeys("${first}");
        reader.readKeys("${second}");

        assertEquals(List.of("second"), reader.keys());
    }

    @Test
    void readKeysWithCustomTokenUsesItsSequences() {
        var custom = new ConfigurationItemReaderImpl(new CustomToken("{{", "}}"));

        assertEquals(List.of("a"), custom.readKeys("{{a}} ${b}"));
    }

    @Test
    void readKeysWithCustomEscapeSequenceSkipsOnlyItsEscapedItems() {
        var withEscape = new ConfigurationItemReaderImpl(new CustomToken("{{", "}}", "\\"));
        var withoutEscape = new ConfigurationItemReaderImpl(new CustomToken("{{", "}}"));

        assertEquals(List.of("b"), withEscape.readKeys("\\{{a}} ${{b}}"));
        assertEquals(List.of("a", "b"), withoutEscape.readKeys("\\{{a}} ${{b}}"));
    }

    @Test
    void readKeysFromSeveralTextsKeepsTheKeysOfAllOfThem() {
        reader.readKeys("${old}");

        var keys = reader.readKeys(List.of("${a} ${b}", "", "${c", "}${d}", "${a}"));

        assertEquals(List.of("a", "b", "d", "a"), keys);
        assertEquals(keys, reader.keys());
    }

    @Test
    void readKeysFromSeveralTextsNullArgumentsThrow() {
        assertThrows(NullPointerException.class, () -> reader.readKeys((Iterable<String>) null));
        assertThrows(IllegalArgumentException.class, () -> reader.readKeys(Arrays.asList("${a}", null)));
    }

    @Test
    void readerNullArgumentsThrow() {
        assertThrows(NullPointerException.class, () -> new ConfigurationItemReaderImpl(null));
        assertThrows(NullPointerException.class, () -> reader.readKeys((InputStream) null));
        assertThrows(NullPointerException.class, () -> reader.readKeys((CharSequence) null));
        assertThrows(NullPointerException.class, () -> reader.readKeys((ByteBuffer) null));
    }

    @Test
    void tokenDefaultsAndOverrides() {
        var defaults = new DefaultToken();
        var custom = new CustomToken("<%", "%>");

        assertEquals(ConfigurationItemTokenBase.DEFAULT_START_SEQUENCE, defaults.getStartSequence());
        assertEquals(ConfigurationItemTokenBase.DEFAULT_END_SEQUENCE, defaults.getEndSequence());
        assertEquals(ConfigurationItemTokenBase.DEFAULT_ESCAPE_SEQUENCE, defaults.getEscapeSequence());
        assertEquals("<%", custom.getStartSequence());
        assertEquals("%>", custom.getEndSequence());
        assertNull(custom.getEscapeSequence());
    }

    @Test
    void tokenEmptyEscapeSequenceThrows() {
        assertThrows(IllegalArgumentException.class, () -> new CustomToken("${", "}", ""));
    }

    static Stream<Arguments> invalidSequences() {
        return Stream.of(
                Arguments.of(null, "}", NullPointerException.class),
                Arguments.of("", "}", IllegalArgumentException.class),
                Arguments.of("${", null, NullPointerException.class),
                Arguments.of("${", "", IllegalArgumentException.class));
    }

    @ParameterizedTest
    @MethodSource("invalidSequences")
    void tokenNullOrEmptySequenceThrows(String start, String end, Class<? extends RuntimeException> expected) {
        assertThrows(expected, () -> new CustomToken(start, end));
    }
}
