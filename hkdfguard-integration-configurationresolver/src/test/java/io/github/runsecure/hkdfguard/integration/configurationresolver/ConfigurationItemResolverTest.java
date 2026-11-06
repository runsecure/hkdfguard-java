package io.github.runsecure.hkdfguard.integration.configurationresolver;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.integration.configurationresolver.TestSources.MapValueProvider;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

/** Port of .NET's ConfigurationItemResolverTests. DictionaryValueProvider is replaced by MapValueProvider. */
class ConfigurationItemResolverTest {
    private static final Map<String, String> VALUES = Map.of(
            "Name", "Ada",
            "value 1", "ONE",
            "value2", "TWO",
            "value3", "THREE",
            "Db:Password", "p@ss",
            "Empty", "",
            "Unicode", "café");

    private static final Map<String, String> NESTED = Map.of(
            "Url", "https://${Host}:${Port}/",
            "Host", "${Region}.db.internal",
            "Region", "eu",
            "Port", "5432",
            "Self", "a${Self}",
            "Ping", "${Pong}",
            "Pong", "${Ping}",
            "Escaped", "$${Region}",
            "Missing", "[${ Nope }]",
            "Shrinks", "${Region}!");

    private static final List<String> NESTED_KEYS = List.copyOf(NESTED.values());

    private final ConfigurationResolver resolver = new ReadingResolver(new DefaultToken(), new MapValueProvider(VALUES));

    static Stream<Arguments> resolvedText() {
        return Stream.of(
                Arguments.of("", ""),
                Arguments.of("plain text", "plain text"),
                Arguments.of("${Name}", "Ada"),
                Arguments.of("Hello ${Name}!", "Hello Ada!"),
                Arguments.of("${ Name }", "Ada"),
                Arguments.of("${\tName\n}", "Ada"),
                Arguments.of("${Name}${Name}", "AdaAda"),
                Arguments.of("${Db:Password}", "p@ss"),
                Arguments.of("[${Empty}]", "[]"),
                Arguments.of("ünï ${Unicode} ✓", "ünï café ✓"),
                Arguments.of("this is my ${ value 1 }, and this is ${value2} and lastly this is ${value3}",
                        "this is my ONE, and this is TWO and lastly this is THREE"));
    }

    static Stream<Arguments> partiallyResolvedText() {
        return Stream.of(
                Arguments.of("${Name}} extra", "Ada} extra"),
                Arguments.of("${Name} then ${unterminated", "Ada then ${unterminated"),
                Arguments.of("${} then ${Name}", "${} then Ada"));
    }

    static Stream<Arguments> resolvedAndPartiallyResolvedText() {
        return Stream.concat(resolvedText(), partiallyResolvedText());
    }

    @ParameterizedTest
    @MethodSource("resolvedAndPartiallyResolvedText")
    void resolveCharsReplacesItems(String source, String expected) {
        assertEquals(expected, resolveChars(resolver, source));
    }

    @ParameterizedTest
    @MethodSource("resolvedAndPartiallyResolvedText")
    void resolveBytesReplacesItems(String source, String expected) {
        assertEquals(expected, resolveBytes(resolver, source));
    }

    @ParameterizedTest
    @ValueSource(strings = {"${}", "${ }", "start ${Name", "} stray end }", "$ {Name} $Name {Name}"})
    void resolveCharsCopiesTextWithoutCompleteItemsUnchanged(String source) {
        assertEquals(source, resolveChars(resolver, source));
    }

    @ParameterizedTest
    @ValueSource(strings = {"${}", "${ }", "start ${Name", "} stray end }", "$ {Name} $Name {Name}"})
    void resolveBytesCopiesTextWithoutCompleteItemsUnchanged(String source) {
        assertEquals(source, resolveBytes(resolver, source));
    }

    @Test
    void resolveCharsReturnsCountAndLeavesRestOfDestinationUntouched() {
        var destination = filled('#', 16);

        var written = resolver.resolve("x=${Name}", destination);

        assertEquals(5, written);
        assertEquals("x=Ada###########", new String(destination));
    }

    @Test
    void resolveBytesReturnsCountAndLeavesRestOfDestinationUntouched() {
        var destination = filled((byte) '#', 8);

        var written = resolver.resolve(utf8("${Unicode}"), destination);

        assertEquals(5, written);
        assertEquals("café###", new String(destination, StandardCharsets.UTF_8));
    }

    @Test
    void resolveCharsSucceedsWhenDestinationIsExactlyTheResolvedLength() {
        assertEquals("x=Ada", resolveChars(resolver, "x=${Name}", 5));
    }

    @Test
    void resolveBytesSucceedsWhenDestinationIsExactlyTheResolvedLength() {
        // "café" is 4 characters but 5 UTF-8 bytes.
        assertEquals("x=café", resolveBytes(resolver, "x=${Unicode}", 7));
    }

    @Test
    void resolveEmptySourceIntoEmptyDestinationWritesNothing() {
        assertEquals(0, resolver.resolve("", new char[0]));
        assertEquals(0, resolver.resolve(new byte[0], new byte[0]));
    }

    static Stream<Arguments> tokenSequences() {
        return Stream.of(
                Arguments.of("{{", "}}", "{{Name}} and ${Name}", "Ada and ${Name}"),
                Arguments.of("{{", "}}", "{{ Name }}{{Name}", "Ada{{Name}"),
                Arguments.of("<%", "%>", "<%Db:Password%>", "p@ss"),
                Arguments.of("«", "»", "« Unicode » and «Name»", "café and Ada"));
    }

    @ParameterizedTest
    @MethodSource("tokenSequences")
    void resolveUsesTheTokensStartAndEndSequences(String start, String end, String source, String expected) {
        var custom = new ReadingResolver(new CustomToken(start, end), new MapValueProvider(VALUES));

        assertEquals(expected, resolveChars(custom, source));
        assertEquals(expected, resolveBytes(custom, source));
    }

    @Test
    void resolveCharsWritesValuesDirectlyIntoTheDestination() {
        var spy = new SpyValueProvider(VALUES);
        var reading = new ReadingResolver(new DefaultToken(), spy);

        assertEquals("ab-Ada-TWO", resolveChars(reading, "ab-${Name}-${value2}", 32));

        assertEquals(List.of("Name", "value2"), spy.tryGetCharsCalls);
        assertEquals(List.of(32 - 3, 32 - 7), spy.bufferLengths);
        assertTrue(spy.findValueCalls.isEmpty());
        assertTrue(spy.tryGetBytesCalls.isEmpty());
    }

    @Test
    void resolveBytesWritesValuesDirectlyIntoTheDestination() {
        var spy = new SpyValueProvider(VALUES);
        var reading = new ReadingResolver(new DefaultToken(), spy);

        assertEquals("ü-café", resolveBytes(reading, "ü-${Unicode}", 32));

        assertEquals(List.of("Unicode"), spy.tryGetBytesCalls);
        assertEquals(List.of(32 - 3), spy.bufferLengths);
        assertTrue(spy.findValueCalls.isEmpty());
        assertTrue(spy.tryGetCharsCalls.isEmpty());
    }

    static Stream<Arguments> failingResolves() {
        return Stream.of(
                Arguments.of("${Name} ${missing}", "missing", 64),
                Arguments.of("${Name} ${value2}", "value2", 5));
    }

    @ParameterizedTest
    @MethodSource("failingResolves")
    void resolveNeverReadsValuesAsStringsEvenWhenItFails(String source, String failingKey, int destinationLength) {
        var spy = new SpyValueProvider(VALUES);
        var reading = new ReadingResolver(new DefaultToken(), spy);

        assertThrows(RuntimeException.class, () -> resolveChars(reading, source, destinationLength));
        assertThrows(RuntimeException.class, () -> resolveBytes(reading, source, destinationLength));

        assertEquals(List.of("Name", failingKey), spy.tryGetCharsCalls);
        assertEquals(List.of("Name", failingKey), spy.tryGetBytesCalls);
        assertTrue(spy.findValueCalls.isEmpty());
    }

    @Test
    void constructorNullTokenThrows() {
        var reader = new ConfigurationItemReaderImpl(new DefaultToken());
        var provider = new MapValueProvider(VALUES);

        var exception = assertThrows(NullPointerException.class, () -> new ConfigurationItemResolver(null, reader, provider));
        var listException = assertThrows(NullPointerException.class, () -> new ConfigurationItemResolver(null, reader, List.of(provider)));

        assertEquals("token", exception.getMessage());
        assertEquals("token", listException.getMessage());
    }

    @Test
    void constructorNullReaderThrows() {
        var provider = new MapValueProvider(VALUES);

        var exception = assertThrows(NullPointerException.class, () -> new ConfigurationItemResolver(new DefaultToken(), null, provider));
        var listException = assertThrows(NullPointerException.class,
                () -> new ConfigurationItemResolver(new DefaultToken(), null, List.of(provider)));

        assertEquals("reader", exception.getMessage());
        assertEquals("reader", listException.getMessage());
    }

    @Test
    void constructorNullValueProviderThrows() {
        var reader = new ConfigurationItemReaderImpl(new DefaultToken());

        var exception = assertThrows(NullPointerException.class,
                () -> new ConfigurationItemResolver(new DefaultToken(), reader, (ValueProvider[]) null));
        var listException = assertThrows(NullPointerException.class,
                () -> new ConfigurationItemResolver(new DefaultToken(), reader, (Iterable<ValueProvider>) null));

        assertEquals("valueProviders", exception.getMessage());
        assertEquals("valueProviders", listException.getMessage());
    }

    @Test
    void constructorNoValueProvidersThrows() {
        var reader = new ConfigurationItemReaderImpl(new DefaultToken());

        assertThrows(IllegalArgumentException.class, () -> new ConfigurationItemResolver(new DefaultToken(), reader));
        assertThrows(IllegalArgumentException.class, () -> new ConfigurationItemResolver(new DefaultToken(), reader, List.of()));
    }

    @Test
    void constructorNullAmongValueProvidersThrows() {
        var reader = new ConfigurationItemReaderImpl(new DefaultToken());
        var provider = new MapValueProvider(VALUES);

        assertThrows(IllegalArgumentException.class, () -> new ConfigurationItemResolver(new DefaultToken(), reader, provider, null));
        assertThrows(IllegalArgumentException.class,
                () -> new ConfigurationItemResolver(new DefaultToken(), reader, Arrays.asList(provider, null)));
    }

    @Test
    void resolveMultipleProvidersUsesTheFirstProviderThatHasTheKey() {
        var high = new SpyValueProvider(Map.of("Name", "Grace"));
        var low = new SpyValueProvider(VALUES);
        var reading = new ReadingResolver(new DefaultToken(), high, low);

        assertEquals("Grace p@ss", resolveChars(reading, "${Name} ${Db:Password}"));
        assertEquals("Grace p@ss", resolveBytes(reading, "${Name} ${Db:Password}"));

        assertEquals(List.of("Name", "Db:Password"), high.tryGetCharsCalls);
        assertEquals(List.of("Db:Password"), low.tryGetCharsCalls);
        assertEquals(List.of("Name", "Db:Password"), high.tryGetBytesCalls);
        assertEquals(List.of("Db:Password"), low.tryGetBytesCalls);
    }

    @Test
    void resolveMultipleProvidersNoneHasTheKeyThrowsNotFound() {
        var reading = new ReadingResolver(new DefaultToken(), new MapValueProvider(Map.of("Name", "Grace")), new MapValueProvider(VALUES));

        var charException = assertThrows(ConfigurationKeyException.class, () -> resolveChars(reading, "${Name} ${missing}"));
        var byteException = assertThrows(ConfigurationKeyException.class, () -> resolveBytes(reading, "${Name} ${missing}"));

        assertKeyException(charException, "missing", ConfigurationKeyError.NOT_FOUND, 8);
        assertKeyException(byteException, "missing", ConfigurationKeyError.NOT_FOUND, 8);
    }

    @Test
    void resolveMultipleProvidersValueTooLargeInTheFirstProviderDoesNotFallThrough() {
        var high = new MapValueProvider(Map.of("Name", "Grace Hopper"));
        var low = new SpyValueProvider(VALUES);
        var reading = new ReadingResolver(new DefaultToken(), high, low);

        assertThrows(DestinationTooSmallException.class, () -> resolveChars(reading, "${Name}", 5));
        assertThrows(DestinationTooSmallException.class, () -> resolveBytes(reading, "${Name}", 5));

        assertTrue(low.tryGetCharsCalls.isEmpty());
        assertTrue(low.tryGetBytesCalls.isEmpty());
    }

    static Stream<Arguments> missingItems() {
        return Stream.of(
                Arguments.of("${missing}", "${missing}"),
                Arguments.of("a ${ missing } b ${Name}", "a ${ missing } b Ada"),
                Arguments.of("${Name}${missing}${Name}", "Ada${missing}Ada"),
                Arguments.of("é ${missing} ${Unicode}", "é ${missing} café"));
    }

    @ParameterizedTest
    @MethodSource("missingItems")
    void resolveIgnoreUnresolvablePlaceholdersCopiesMissingItemsUnchanged(String source, String expected) {
        var lenient = new ReadingResolver(new DefaultToken(), new MapValueProvider(VALUES)).ignoringUnresolvablePlaceholders();

        assertEquals(expected, resolveChars(lenient, source));
        assertEquals(expected, resolveBytes(lenient, source));
    }

    @Test
    void resolveIgnoreUnresolvablePlaceholdersCopiesTheTokensOwnSequences() {
        var lenient = new ReadingResolver(new CustomToken("{{", "}}"), new MapValueProvider(VALUES)).ignoringUnresolvablePlaceholders();

        assertEquals("Ada {{ missing }}", resolveChars(lenient, "{{Name}} {{ missing }}"));
        assertEquals("Ada {{ missing }}", resolveBytes(lenient, "{{Name}} {{ missing }}"));
    }

    @Test
    void resolveIgnoreUnresolvablePlaceholdersKeyNotReadByTheReaderStillThrows() {
        var reader = new ConfigurationItemReaderImpl(new DefaultToken());
        var spy = new SpyValueProvider(VALUES);
        var lenient = new ConfigurationItemResolver(new DefaultToken(), reader, spy).withIgnoreUnresolvablePlaceholders(true);
        reader.readKeys("${Name}");

        var exception = assertThrows(ConfigurationKeyException.class, () -> resolveChars(lenient, "${Name} ${Db:Password}"));

        assertKeyException(exception, "Db:Password", ConfigurationKeyError.NOT_ALLOWED, 8);
        assertEquals(List.of("Name"), spy.tryGetCharsCalls);
    }

    @Test
    void resolveIgnoreUnresolvablePlaceholdersProviderErrorStillPropagates() {
        var spy = new SpyValueProvider(VALUES, new ConfigurationKeyException("Name", ConfigurationKeyError.VALUE_UNSTABLE));
        var lenient = new ReadingResolver(new DefaultToken(), spy).ignoringUnresolvablePlaceholders();

        var exception = assertThrows(ConfigurationKeyException.class, () -> resolveChars(lenient, "${Name}"));

        assertEquals(ConfigurationKeyError.VALUE_UNSTABLE, exception.getError());
    }

    @ParameterizedTest
    @ValueSource(ints = {9, 13})
    void resolveIgnoreUnresolvablePlaceholdersDestinationTooSmallForTheItemThrowsAndClearsDestination(int destinationLength) {
        var lenient = new ReadingResolver(new DefaultToken(), new MapValueProvider(VALUES)).ignoringUnresolvablePlaceholders();
        var chars = filled('#', destinationLength);
        var bytes = filled((byte) '#', destinationLength);

        assertThrows(DestinationTooSmallException.class, () -> lenient.resolve("Ada ${missing}", chars));
        assertThrows(DestinationTooSmallException.class, () -> lenient.resolve(utf8("Ada ${missing}"), bytes));

        assertArrayEquals(new char[destinationLength], chars);
        assertArrayEquals(new byte[destinationLength], bytes);
    }

    @Test
    void resolveIgnoreUnresolvablePlaceholdersIsOffByDefault() {
        var strict = new ConfigurationItemResolver(new DefaultToken(), new ConfigurationItemReaderImpl(new DefaultToken()), new MapValueProvider(VALUES));

        assertFalse(strict.ignoreUnresolvablePlaceholders());
    }

    @Test
    void resolveKeysReadFromATrustedTemplateAreResolvedInAnotherSource() {
        var allowListed = AllowListed.create();
        allowListed.reader.readKeys("${Name} ${ Db:Password }");

        assertEquals("p@ss for Ada", resolveChars(allowListed.resolver, "${Db:Password} for ${Name}"));
        assertEquals("p@ss for Ada", resolveBytes(allowListed.resolver, "${Db:Password} for ${Name}"));
    }

    static Stream<Arguments> rejectedKeys() {
        return Stream.of(
                Arguments.of("${Db:Password}", "Db:Password", 0, 0),
                Arguments.of("${Name} then ${Db:Password}", "Db:Password", 13, 13),
                Arguments.of("${name}", "name", 0, 0),
                Arguments.of("ü ${ Db:Password }", "Db:Password", 2, 3));
    }

    @ParameterizedTest
    @MethodSource("rejectedKeys")
    void resolveKeyNotReadByTheReaderThrowsWithoutAskingTheProvider(String source, String rejectedKey, int charIndex, int byteIndex) {
        var allowListed = AllowListed.create();
        allowListed.reader.readKeys("${Name}");
        var chars = filled('#', 64);
        var bytes = filled((byte) '#', 64);

        var charException = assertThrows(ConfigurationKeyException.class, () -> allowListed.resolver.resolve(source, chars));
        var byteException = assertThrows(ConfigurationKeyException.class, () -> allowListed.resolver.resolve(utf8(source), bytes));

        assertKeyException(charException, rejectedKey, ConfigurationKeyError.NOT_ALLOWED, charIndex);
        assertKeyException(byteException, rejectedKey, ConfigurationKeyError.NOT_ALLOWED, byteIndex);
        assertFalse(allowListed.spy.tryGetCharsCalls.contains(rejectedKey));
        assertFalse(allowListed.spy.tryGetBytesCalls.contains(rejectedKey));
        assertArrayEquals(new char[64], chars);
        assertArrayEquals(new byte[64], bytes);
    }

    @Test
    void resolveBeforeAnyKeysAreReadResolvesOnlyTextWithoutItems() {
        var allowListed = AllowListed.create();

        assertEquals("plain ${} text", resolveChars(allowListed.resolver, "plain ${} text"));
        assertThrows(ConfigurationKeyException.class, () -> resolveChars(allowListed.resolver, "${Name}"));
        assertTrue(allowListed.spy.tryGetCharsCalls.isEmpty());
    }

    @Test
    void resolveUsesTheReadersMostRecentKeys() {
        var allowListed = AllowListed.create();
        allowListed.reader.readKeys("${Name}");
        assertEquals("Ada", resolveChars(allowListed.resolver, "${Name}"));

        allowListed.reader.readKeys("${value2}");

        assertEquals("TWO", resolveChars(allowListed.resolver, "${value2}"));
        assertThrows(ConfigurationKeyException.class, () -> resolveChars(allowListed.resolver, "${Name}"));
    }

    static Stream<Arguments> missingKeysChars() {
        return Stream.of(
                Arguments.of("${missing}", "missing", 0),
                Arguments.of("${Name} then ${ missing }", "missing", 13),
                Arguments.of("${name}", "name", 0),
                Arguments.of("${a${Name}}", "a${Name", 0),
                Arguments.of("é ${missing}", "missing", 2));
    }

    @ParameterizedTest
    @MethodSource("missingKeysChars")
    void resolveCharsMissingKeyThrowsAndClearsDestination(String source, String missingKey, int sourceIndex) {
        var destination = filled('#', 64);

        var exception = assertThrows(ConfigurationKeyException.class, () -> resolver.resolve(source, destination));

        assertKeyException(exception, missingKey, ConfigurationKeyError.NOT_FOUND, sourceIndex);
        assertArrayEquals(new char[64], destination);
    }

    static Stream<Arguments> missingKeysBytes() {
        return Stream.of(
                Arguments.of("${missing}", "missing", 0),
                Arguments.of("${Name} then ${ missing }", "missing", 13),
                Arguments.of("${name}", "name", 0),
                Arguments.of("${a${Name}}", "a${Name", 0),
                Arguments.of("é ${missing}", "missing", 3));
    }

    @ParameterizedTest
    @MethodSource("missingKeysBytes")
    void resolveBytesMissingKeyThrowsAndClearsDestination(String source, String missingKey, int sourceIndex) {
        var destination = filled((byte) '#', 64);

        var exception = assertThrows(ConfigurationKeyException.class, () -> resolver.resolve(utf8(source), destination));

        assertKeyException(exception, missingKey, ConfigurationKeyError.NOT_FOUND, sourceIndex);
        assertArrayEquals(new byte[64], destination);
    }

    static Stream<Arguments> tooSmallChars() {
        return Stream.of(
                Arguments.of("literal too long", 4),
                Arguments.of("ab ${Name}", 2),
                Arguments.of("ab ${Name}", 5),
                Arguments.of("${Name} trailing text", 6),
                Arguments.of("${Db:Password} ${Name}", 6),
                Arguments.of("x", 0));
    }

    @ParameterizedTest
    @MethodSource("tooSmallChars")
    void resolveCharsDestinationTooSmallThrowsAndClearsDestination(String source, int destinationLength) {
        var destination = filled('#', destinationLength);

        assertThrows(DestinationTooSmallException.class, () -> resolver.resolve(source, destination));

        assertArrayEquals(new char[destinationLength], destination);
    }

    static Stream<Arguments> tooSmallBytes() {
        return Stream.of(
                Arguments.of("literal too long", 4),
                Arguments.of("ab ${Name}", 2),
                Arguments.of("ab ${Name}", 5),
                Arguments.of("${Unicode}", 4),
                Arguments.of("${Db:Password} ${Name}", 6),
                Arguments.of("x", 0));
    }

    @ParameterizedTest
    @MethodSource("tooSmallBytes")
    void resolveBytesDestinationTooSmallThrowsAndClearsDestination(String source, int destinationLength) {
        var destination = filled((byte) '#', destinationLength);

        assertThrows(DestinationTooSmallException.class, () -> resolver.resolve(utf8(source), destination));

        assertArrayEquals(new byte[destinationLength], destination);
    }

    @Test
    void resolveProviderThrowsPropagatesAndClearsDestination() {
        var spy = new SpyValueProvider(VALUES, new IllegalStateException("provider failed"));
        var reading = new ReadingResolver(new DefaultToken(), spy);
        var chars = filled('#', 16);
        var bytes = filled((byte) '#', 16);

        assertThrows(IllegalStateException.class, () -> reading.resolve("ab ${Name}", chars));
        assertThrows(IllegalStateException.class, () -> reading.resolve(utf8("ab ${Name}"), bytes));

        assertArrayEquals(new char[16], chars);
        assertArrayEquals(new byte[16], bytes);
    }

    static Stream<Arguments> escapedStartSequences() {
        return Stream.of(
                Arguments.of("$${Name}", "${Name}"),
                Arguments.of("$${", "${"),
                Arguments.of("$${Name} is ${Name}", "${Name} is Ada"),
                Arguments.of("$$${Name}", "$${Name}"),
                Arguments.of("$${a ${Name}}", "${a Ada}"),
                Arguments.of("$ ${Name} $$", "$ Ada $$"),
                Arguments.of("é $${Unicode}", "é ${Unicode}"));
    }

    @ParameterizedTest
    @MethodSource("escapedStartSequences")
    void resolveEscapedStartSequenceIsCopiedWithoutTheEscape(String source, String expected) {
        assertEquals(expected, resolveChars(resolver, source));
        assertEquals(expected, resolveBytes(resolver, source));
    }

    @Test
    void resolveEscapedItemIsNotAKeySoItNeedsNoPermission() {
        var allowListed = AllowListed.create();
        allowListed.reader.readKeys("${Name}");

        assertEquals("Ada ${Db:Password}", resolveChars(allowListed.resolver, "${Name} $${Db:Password}"));
        assertEquals("Ada ${Db:Password}", resolveBytes(allowListed.resolver, "${Name} $${Db:Password}"));

        assertEquals(List.of("Name"), allowListed.spy.tryGetCharsCalls);
        assertEquals(List.of("Name"), allowListed.spy.tryGetBytesCalls);
    }

    static Stream<Arguments> escapeSequences() {
        return Stream.of(
                Arguments.of(null, "${{Name}} \\{{Name}}", "$Ada \\Ada"),
                Arguments.of("\\", "${{Name}} \\{{Name}}", "$Ada {{Name}}"));
    }

    @ParameterizedTest
    @MethodSource("escapeSequences")
    void resolveUsesTheTokensEscapeSequence(String escape, String source, String expected) {
        var custom = new ReadingResolver(new CustomToken("{{", "}}", escape), new MapValueProvider(VALUES));

        assertEquals(expected, resolveChars(custom, source));
        assertEquals(expected, resolveBytes(custom, source));
    }

    @Test
    void maxResolutionDepthDefaultsToOneAndMustBePositive() {
        var strict = new ConfigurationItemResolver(new DefaultToken(), new ConfigurationItemReaderImpl(new DefaultToken()), new MapValueProvider(VALUES));

        assertEquals(1, strict.maxResolutionDepth());
        assertThrows(IllegalArgumentException.class, () -> strict.withMaxResolutionDepth(0));
    }

    static Stream<Arguments> nestedItems() {
        return Stream.of(
                Arguments.of(1, "${Url}", "https://${Host}:${Port}/"),
                Arguments.of(2, "${Url}", "https://${Region}.db.internal:5432/"),
                Arguments.of(3, "${Url}", "https://eu.db.internal:5432/"),
                Arguments.of(10, "go ${Url} now", "go https://eu.db.internal:5432/ now"),
                Arguments.of(1, "${Escaped}", "$${Region}"),
                Arguments.of(2, "${Escaped}", "${Region}"),
                Arguments.of(2, "${Ping}", "${Ping}"),
                Arguments.of(2, "${Port}${Host}", "5432eu.db.internal"));
    }

    @ParameterizedTest
    @MethodSource("nestedItems")
    void resolveItemsInValuesAreResolvedUpToTheMaximumDepth(int depth, String source, String expected) {
        var nested = createNested(depth);

        assertEquals(expected, resolveChars(nested, source));
        assertEquals(expected, resolveBytes(nested, source));
    }

    static Stream<Arguments> cycles() {
        return Stream.of(
                Arguments.of(2, "${Self}", "Self", 0),
                Arguments.of(5, "x ${Self}", "Self", 2),
                Arguments.of(3, "${Ping}", "Ping", 0),
                Arguments.of(10, "ab ${Pong}", "Pong", 3));
    }

    @ParameterizedTest
    @MethodSource("cycles")
    void resolveValueThatLeadsBackToItsKeyThrowsCycleAndClearsDestination(int depth, String source, String key, int sourceIndex) {
        var nested = createNested(depth);
        var chars = filled('#', 256);
        var bytes = filled((byte) '#', 256);

        var charException = assertThrows(ConfigurationKeyException.class, () -> nested.resolve(source, chars));
        var byteException = assertThrows(ConfigurationKeyException.class, () -> nested.resolve(utf8(source), bytes));

        assertKeyException(charException, key, ConfigurationKeyError.CYCLE, sourceIndex);
        assertKeyException(byteException, key, ConfigurationKeyError.CYCLE, sourceIndex);
        assertArrayEquals(new char[256], chars);
        assertArrayEquals(new byte[256], bytes);
    }

    @Test
    void resolveKeyInAValueMustBeAllowed() {
        var spy = new SpyValueProvider(NESTED);
        var reading = new ReadingResolver(new DefaultToken(), spy).withMaxResolutionDepth(3);

        var exception = assertThrows(ConfigurationKeyException.class, () -> resolveChars(reading, "go ${Host}"));

        assertKeyException(exception, "Region", ConfigurationKeyError.NOT_ALLOWED, 3);
        assertEquals(List.of("Host"), spy.tryGetCharsCalls);
    }

    @Test
    void resolveMissingKeyInAValueThrowsWithTheSourceItemsIndexOrIsKeptWhenIgnored() {
        var strict = createNested(2);
        var lenient = new ReadingResolver(new DefaultToken(), new MapValueProvider(NESTED))
                .withMaxResolutionDepth(2)
                .ignoringUnresolvablePlaceholders()
                .alsoAllowing(NESTED_KEYS);

        var exception = assertThrows(ConfigurationKeyException.class, () -> resolveBytes(strict, "é ${Missing}"));

        assertKeyException(exception, "Nope", ConfigurationKeyError.NOT_FOUND, 3);
        assertEquals("é [${ Nope }]", resolveChars(lenient, "é ${Missing}"));
        assertEquals("é [${ Nope }]", resolveBytes(lenient, "é ${Missing}"));
    }

    @Test
    void resolveValueThatShrinksWhenResolvedLeavesNoTraceOfTheRawValue() {
        var nested = createNested(2);
        var chars = filled('#', 64);
        var bytes = filled((byte) '#', 64);

        var charsWritten = nested.resolve("${Shrinks}", chars);
        var bytesWritten = nested.resolve(utf8("${Shrinks}"), bytes);

        assertEquals("eu!", new String(chars, 0, charsWritten));
        assertEquals("eu!", new String(bytes, 0, bytesWritten, StandardCharsets.UTF_8));
        assertFalse(new String(chars).contains("Region"));
        assertFalse(new String(bytes, StandardCharsets.UTF_8).contains("Region"));
        var rawLength = "${Region}!".length();
        assertEquals("#".repeat(64 - rawLength), new String(chars, rawLength, 64 - rawLength));
    }

    @Test
    void resolveItemsInValuesAreWrittenWithoutReadingValuesAsStrings() {
        var spy = new SpyValueProvider(NESTED);
        var reading = new ReadingResolver(new DefaultToken(), spy).withMaxResolutionDepth(3).alsoAllowing(NESTED_KEYS);

        assertEquals("https://eu.db.internal:5432/", resolveChars(reading, "${Url}"));

        assertEquals(List.of("Url", "Host", "Region", "Port"), spy.tryGetCharsCalls);
        assertTrue(spy.findValueCalls.isEmpty());
    }

    private static ReadingResolver createNested(int depth) {
        return new ReadingResolver(new DefaultToken(), new MapValueProvider(NESTED)).withMaxResolutionDepth(depth).alsoAllowing(NESTED_KEYS);
    }

    static void assertKeyException(ConfigurationKeyException exception, String key, ConfigurationKeyError error, int sourceIndex) {
        assertEquals(key, exception.getKey());
        assertEquals(error, exception.getError());
        assertEquals(sourceIndex, exception.getSourceIndex().orElseThrow());
        assertEquals("The configuration item at index " + sourceIndex + " could not be resolved (" + error.name() + ").", exception.getMessage());
        assertFalse(exception.getMessage().contains(key));
    }

    /** A resolver over a reader the test fills, and a spy provider. */
    private record AllowListed(ConfigurationItemReaderImpl reader, ConfigurationItemResolver resolver, SpyValueProvider spy) {
        static AllowListed create() {
            var reader = new ConfigurationItemReaderImpl(new DefaultToken());
            var spy = new SpyValueProvider(VALUES);
            return new AllowListed(reader, new ConfigurationItemResolver(new DefaultToken(), reader, spy), spy);
        }
    }

    static String resolveChars(ConfigurationResolver resolver, String source) {
        return resolveChars(resolver, source, 1024);
    }

    static String resolveChars(ConfigurationResolver resolver, String source, int destinationLength) {
        var destination = new char[destinationLength];
        var written = resolver.resolve(source, destination);
        return new String(destination, 0, written);
    }

    static String resolveBytes(ConfigurationResolver resolver, String source) {
        return resolveBytes(resolver, source, 1024);
    }

    static String resolveBytes(ConfigurationResolver resolver, String source, int destinationLength) {
        var destination = new byte[destinationLength];
        var written = resolver.resolve(utf8(source), destination);
        return new String(destination, 0, written, StandardCharsets.UTF_8);
    }

    static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    static char[] filled(char value, int length) {
        var array = new char[length];
        Arrays.fill(array, value);
        return array;
    }

    static byte[] filled(byte value, int length) {
        var array = new byte[length];
        Arrays.fill(array, value);
        return array;
    }
}
