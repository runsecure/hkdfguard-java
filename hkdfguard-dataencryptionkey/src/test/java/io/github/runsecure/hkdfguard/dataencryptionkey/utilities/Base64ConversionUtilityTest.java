package io.github.runsecure.hkdfguard.dataencryptionkey.utilities;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatException;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class Base64ConversionUtilityTest {
    @ParameterizedTest
    @CsvSource({"AAAA,true", "AAA=,true", "AA==,true", "'',true", "not valid base64!!!,false", "AAA,false", "A===,false", "AA=A,false", "=AAA,false"})
    void isBase64_Chars_ValidatesStrictly(String input, boolean expected) {
        assertEquals(expected, Base64ConversionUtility.isBase64(input));
    }

    @Test
    void isBase64_Bytes_ValidatesCorrectly() {
        assertTrue(Base64ConversionUtility.isBase64("AAAA".getBytes(StandardCharsets.US_ASCII)));
        assertFalse(Base64ConversionUtility.isBase64("!!!!".getBytes(StandardCharsets.US_ASCII)));
        assertFalse(Base64ConversionUtility.isBase64(new byte[] {(byte) 0xC3, (byte) 0xA9, 'A', 'A'}));
    }

    @Test
    void getBinaryLength_EmptyInput_ReturnsZero() {
        assertEquals(0, Base64ConversionUtility.getBinaryLength(""));
    }

    @ParameterizedTest
    @CsvSource({"QQ==,1", "QUI=,2", "QUJD,3"})
    void getBinaryLength_ComputesCorrectLength(String base64, int expected) {
        assertEquals(expected, Base64ConversionUtility.getBinaryLength(base64));
    }

    @Test
    void getBinaryLength_NotMultipleOfFour_Throws() {
        assertThrows(EncryptedFormatException.class, () -> Base64ConversionUtility.getBinaryLength("AAA"));
    }

    @ParameterizedTest
    @CsvSource({"0,0", "1,4", "2,4", "3,4", "4,8"})
    void getBase64Length_ComputesCorrectLength(int byteLength, int expected) {
        assertEquals(expected, Base64ConversionUtility.getBase64Length(new byte[byteLength]));
    }

    @Test
    void toBase64String_ThenFromBase64_RoundTrips() {
        var data = "hello world".getBytes(StandardCharsets.UTF_8);
        var base64 = Base64ConversionUtility.toBase64String(data);
        var destination = new byte[Base64ConversionUtility.getBinaryLength(base64)];

        assertEquals(data.length, Base64ConversionUtility.fromBase64(base64, destination));
        assertArrayEquals(data, destination);
    }

    @Test
    void fromBase64_WithInvalidInputOrTooSmallDestination_Throws() {
        assertThrows(EncryptedFormatException.class, () -> Base64ConversionUtility.fromBase64("not valid base64!!!", new byte[16]));
        assertThrows(EncryptedFormatException.class, () -> Base64ConversionUtility.fromBase64("QUJD", new byte[1]));
        assertThrows(EncryptedFormatException.class, () -> Base64ConversionUtility.fromBase64("QUJ", new byte[16])); // unpadded
    }

    @Test
    void toBase64Chars_ThenFromBase64_RoundTrips() {
        var data = "round trip".getBytes(StandardCharsets.UTF_8);
        var destination = new char[Base64ConversionUtility.getBase64Length(data)];

        var written = Base64ConversionUtility.toBase64Chars(data, destination);
        assertEquals(destination.length, written);

        var chars = CharBuffer.wrap(destination, 0, written);
        var decoded = new byte[Base64ConversionUtility.getBinaryLength(chars)];
        Base64ConversionUtility.fromBase64(chars, decoded);
        assertArrayEquals(data, decoded);
    }

    @Test
    void toBase64Chars_WithTooSmallDestination_Throws() {
        assertThrows(IllegalArgumentException.class, () -> Base64ConversionUtility.toBase64Chars("hello".getBytes(StandardCharsets.UTF_8), new char[1]));
    }
}
