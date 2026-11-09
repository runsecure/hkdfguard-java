package io.github.runsecure.hkdfguard.integration.configurationresolver;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.runsecure.hkdfguard.integration.configurationresolver.TestSources.MapValueProvider;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Port of the parts of .NET's JsonConfigurationScenarioTests that use only ported classes: the
 * "dictionary" provider is replaced by MapValueProvider, the template is held in memory instead of
 * on disk, and the resolved text is compared directly instead of being loaded as JSON.
 */
class TemplateScenarioTest {
    private static final String TEMPLATE = """
            {
              "ConnectionStrings": {
                "Default": "Host=${Database:Host};Port=${ Database:Port };Password=${Database:Password}"
              },
              "Greeting": "${Greeting} wörld",
              "Literal": "${} and $ {not an item}"
            }
            """;

    private static final String RESOLVED = """
            {
              "ConnectionStrings": {
                "Default": "Host=db.internal;Port=5432;Password=s3cr\\"t!"
              },
              "Greeting": "héllo wörld",
              "Literal": "${} and $ {not an item}"
            }
            """;

    private static final Map<String, String> VALUES = Map.of(
            "Database:Host", "db.internal",
            "Database:Port", "5432",
            "Database:Password", "s3cr\\\"t!",
            "Greeting", "héllo");

    private static ConfigurationItemResolver createResolver(ConfigurationItemTokenBase token, String template) {
        var reader = new ConfigurationItemReaderImpl(token);
        reader.readKeys(template);
        return new ConfigurationItemResolver(token, reader, new MapValueProvider(VALUES));
    }

    @Test
    void resolvedCharTemplateIsTheExpectedText() {
        var resolver = createResolver(new DefaultToken(), TEMPLATE);

        assertEquals(RESOLVED, resolveChars(resolver, TEMPLATE));
    }

    @Test
    void resolvedByteTemplateIsTheExpectedText() {
        var resolver = createResolver(new DefaultToken(), TEMPLATE);

        assertEquals(RESOLVED, new String(resolveBytes(resolver, utf8(TEMPLATE)), StandardCharsets.UTF_8));
    }

    @Test
    void readerListsTheKeysInTheTemplate() {
        var reader = new ConfigurationItemReaderImpl(new DefaultToken());
        var expected = List.of("Database:Host", "Database:Port", "Database:Password", "Greeting");

        assertEquals(expected, reader.readKeys(new ByteArrayInputStream(utf8(TEMPLATE))));
        assertEquals(expected, reader.keys());
        assertEquals(expected, reader.readKeys(utf8(TEMPLATE)));
    }

    @Test
    void customTokenResolvesOnlyItsOwnItems() {
        var template = "{ \"Host\": \"{{Database:Host}}\", \"Kept\": \"${Database:Host}\" }";
        var resolver = createResolver(new CustomToken("{{", "}}"), template);

        assertEquals("{ \"Host\": \"db.internal\", \"Kept\": \"${Database:Host}\" }", resolveChars(resolver, template));
    }

    @Test
    void templateWithByteOrderMarkResolves() {
        var bom = new byte[] {(byte) 0xEF, (byte) 0xBB, (byte) 0xBF};
        var template = concat(bom, utf8("{ \"Host\": \"${Database:Host}\" }"));
        var reader = new ConfigurationItemReaderImpl(new DefaultToken());
        assertEquals(List.of("Database:Host"), reader.readKeys(new ByteArrayInputStream(template)));
        var resolver = new ConfigurationItemResolver(new DefaultToken(), reader, new MapValueProvider(VALUES));

        // The byte order mark is copied like any other text, as .NET does.
        assertArrayEquals(concat(bom, utf8("{ \"Host\": \"db.internal\" }")), resolveBytes(resolver, template));
    }

    @Test
    void templateWithMissingValueThrows() {
        var template = "{ \"Value\": \"${Database:Missing}\" }";
        var resolver = createResolver(new DefaultToken(), template);

        var exception = assertThrows(ConfigurationKeyException.class, () -> resolveChars(resolver, template));
        assertThrows(ConfigurationKeyException.class, () -> resolveBytes(resolver, utf8(template)));

        assertEquals("Database:Missing", exception.getKey());
        assertEquals(ConfigurationKeyError.NOT_FOUND, exception.getError());
    }

    @Test
    void destinationTooSmallForAValueThrowsAndClearsTheSecret() {
        var template = "${Database:Password}${Database:Password}";
        var resolver = createResolver(new DefaultToken(), template);
        var chars = new char["s3cr\"t!".length() + 3];
        var bytes = new byte[chars.length];

        assertThrows(DestinationTooSmallException.class, () -> resolver.resolve(template, chars));
        assertThrows(DestinationTooSmallException.class, () -> resolver.resolve(utf8(template), bytes));

        assertArrayEquals(new char[chars.length], chars);
        assertArrayEquals(new byte[bytes.length], bytes);
    }

    @Test
    void destinationTooSmallForTheTemplateTextThrowsAndClearsTheDestination() {
        var resolver = createResolver(new DefaultToken(), TEMPLATE);
        var chars = new char[TEMPLATE.indexOf("${") - 1];
        var bytes = new byte[chars.length];

        assertThrows(DestinationTooSmallException.class, () -> resolver.resolve(TEMPLATE, chars));
        assertThrows(DestinationTooSmallException.class, () -> resolver.resolve(utf8(TEMPLATE), bytes));

        assertArrayEquals(new char[chars.length], chars);
        assertArrayEquals(new byte[bytes.length], bytes);
    }

    @Test
    void templateUsingAKeyOutsideTheTrustedTemplateIsRejected() {
        // The trusted template only asks for the host; a substituted template also asks for the password.
        var trusted = "{ \"Host\": \"${Database:Host}\" }";
        var injected = "{ \"Host\": \"${Database:Host}\", \"Leak\": \"${Database:Password}\" }";
        var resolver = createResolver(new DefaultToken(), trusted);

        assertEquals("{ \"Host\": \"db.internal\" }", new String(resolveBytes(resolver, utf8(trusted)), StandardCharsets.UTF_8));

        var charException = assertThrows(ConfigurationKeyException.class, () -> resolveChars(resolver, injected));
        var byteException = assertThrows(ConfigurationKeyException.class, () -> resolveBytes(resolver, utf8(injected)));

        var leakIndex = injected.indexOf("${Database:Password}");
        for (var exception : List.of(charException, byteException)) {
            assertEquals("Database:Password", exception.getKey());
            assertEquals(ConfigurationKeyError.NOT_ALLOWED, exception.getError());
            assertEquals(leakIndex, exception.getSourceIndex().orElseThrow());
            assertFalse(exception.getMessage().contains("Database:Password"));
        }
    }

    @Test
    void ignoreUnresolvablePlaceholdersLeavesMissingItemsInTheResolvedText() {
        var template = "{ \"Host\": \"${Database:Host}\", \"Optional\": \"${ Feature:Flag }\" }";
        var resolver = createResolver(new DefaultToken(), template).withIgnoreUnresolvablePlaceholders(true);

        assertEquals("{ \"Host\": \"db.internal\", \"Optional\": \"${ Feature:Flag }\" }",
                new String(resolveBytes(resolver, utf8(template)), StandardCharsets.UTF_8));
    }

    @Test
    void unterminatedItemInJsonRunsToTheNextClosingBrace() {
        // JSON's own closing brace ends the item, so the key includes the JSON that follows it.
        var template = "{ \"Value\": \"${unterminated\" }";
        var resolver = createResolver(new DefaultToken(), template);

        var exception = assertThrows(ConfigurationKeyException.class, () -> resolveChars(resolver, template));

        assertEquals("unterminated\"", exception.getKey());
    }

    private static String resolveChars(ConfigurationResolver resolver, String source) {
        var destination = new char[4096];
        var written = resolver.resolve(source, destination);
        return new String(destination, 0, written);
    }

    private static byte[] resolveBytes(ConfigurationResolver resolver, byte[] source) {
        var destination = new byte[4096];
        var written = resolver.resolve(source, destination);
        return Arrays.copyOf(destination, written);
    }

    private static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] concat(byte[] first, byte[] second) {
        var result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }
}
