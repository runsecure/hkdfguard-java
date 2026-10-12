package io.github.runsecure.hkdfguard.abstractions;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class ProtectedConfigurationPurposeTest {
    @Test
    void forKey_PrefixesAndUpperCasesTheFullKeyPath() {
        assertEquals("HkdfGuard.EncryptedConfiguration:CONNECTIONSTRINGS:ADMIN",
                ProtectedConfigurationPurpose.forKey("ConnectionStrings:Admin"));
    }

    @Test
    void forKey_DifferentKeys_GiveDifferentPurposes() {
        assertNotEquals(ProtectedConfigurationPurpose.forKey("ConnectionStrings:Admin"),
                ProtectedConfigurationPurpose.forKey("ConnectionStrings:Reporting"));
    }

    @Test
    void aadFor_IsTheUtf8BytesOfThePurpose() {
        assertArrayEquals(ProtectedConfigurationPurpose.forKey("Database:Password").getBytes(StandardCharsets.UTF_8),
                ProtectedConfigurationPurpose.aadFor("Database:Password"));
    }

    @Test
    void anEmptyOrNullKey_Throws() {
        assertThrows(IllegalArgumentException.class, () -> ProtectedConfigurationPurpose.forKey(""));
        assertThrows(IllegalArgumentException.class, () -> ProtectedConfigurationPurpose.aadFor(""));
        assertThrows(IllegalArgumentException.class, () -> ProtectedConfigurationPurpose.aadFor(CharBuffer.allocate(0)));
        assertThrows(NullPointerException.class, () -> ProtectedConfigurationPurpose.forKey(null));
        assertThrows(NullPointerException.class, () -> ProtectedConfigurationPurpose.aadFor(null));
    }

    @ParameterizedTest
    @ValueSource(strings = {"ConnectionStrings:Admin", "héllo:ünïcode"})
    void aadFor_ACharBuffer_MatchesAString(String key) {
        assertArrayEquals(ProtectedConfigurationPurpose.aadFor(key), ProtectedConfigurationPurpose.aadFor(CharBuffer.wrap(key.toCharArray())));
    }

    @Test
    void aadFor_ALongKey_StillMatchesForKey() {
        var longKey = IntStream.range(0, 60).mapToObj(i -> "Section" + i).collect(Collectors.joining(":"));

        assertArrayEquals(ProtectedConfigurationPurpose.forKey(longKey).getBytes(StandardCharsets.UTF_8),
                ProtectedConfigurationPurpose.aadFor(longKey));
    }

    @ParameterizedTest
    @CsvSource({"secret,SECRET", "Secret,secret", "Connection_Strings:Admin-1,connection_strings:ADMIN-1"})
    void keysDifferingOnlyInAsciiCase_ShareAPurpose(String first, String second) {
        assertEquals(ProtectedConfigurationPurpose.forKey(first), ProtectedConfigurationPurpose.forKey(second));
        assertArrayEquals(ProtectedConfigurationPurpose.aadFor(first), ProtectedConfigurationPurpose.aadFor(second));
    }

    @ParameterizedTest
    @CsvSource({
            "café,CAFÉ",   // non-ASCII case: never merged
            "ſecret,Secret",    // 'ſ' upper-cases to 'S' under Unicode rules, never here
            "ıd,ID",            // dotless i
            "straße,STRASSE",   // ß
    })
    void nonAsciiCaseVariants_NeverShareAPurpose(String first, String second) {
        assertNotEquals(ProtectedConfigurationPurpose.forKey(first), ProtectedConfigurationPurpose.forKey(second));
    }

    @Test
    void forKey_UpperCasesOnlyAsciiLetters_AndCopiesEveryOtherCodeUnitAsIs() {
        assertEquals(ProtectedConfigurationPurpose.PREFIX + ":CAFé:üBER-1_中",
                ProtectedConfigurationPurpose.forKey("café:über-1_中"));
    }

    @Test
    void forKey_NeverMergesKeysThatDifferBeyondAsciiCase_ForAnyCodePoint() {
        // The safety half of the rule, checked exhaustively: equal purposes imply the keys are
        // equal ignoring case.
        var byPurpose = new HashMap<String, String>();
        for (var cp = 0; cp <= 0x10FFFF; cp++) {
            if (cp >= 0xD800 && cp <= 0xDFFF)
                continue;

            var key = Character.toString(cp);
            var purpose = ProtectedConfigurationPurpose.forKey(key);
            var other = byPurpose.putIfAbsent(purpose, key);
            if (other != null)
                assertTrue(key.equalsIgnoreCase(other), String.format("U+%04X shares a purpose with '%s'", cp, other));
        }
    }

    @Test
    void forKeyAndAadFor_RejectAnUnpairedSurrogate() {
        for (var key : new String[] {"Key\uD800Tail", "Key\uDC00Tail", "Key\uD800"}) {
            assertThrows(IllegalArgumentException.class, () -> ProtectedConfigurationPurpose.forKey(key));
            assertThrows(IllegalArgumentException.class, () -> ProtectedConfigurationPurpose.aadFor(key));
        }
    }

    @Test
    void forKeyAndAadFor_AcceptASurrogatePair() {
        var key = "Key😀Tail";

        assertEquals(ProtectedConfigurationPurpose.PREFIX + ":KEY😀TAIL", ProtectedConfigurationPurpose.forKey(key));
        assertArrayEquals(ProtectedConfigurationPurpose.forKey(key).getBytes(StandardCharsets.UTF_8), ProtectedConfigurationPurpose.aadFor(key));
    }

    @Test
    void aadFor_KnownVector_ForCrossLanguagePorts() {
        // Every port must produce exactly these bytes for this key.
        assertArrayEquals("HkdfGuard.EncryptedConfiguration:CONNECTIONSTRINGS:CAFé".getBytes(StandardCharsets.UTF_8),
                ProtectedConfigurationPurpose.aadFor("ConnectionStrings:café"));
    }
}
