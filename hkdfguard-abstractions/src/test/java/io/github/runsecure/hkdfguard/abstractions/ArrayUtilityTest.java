package io.github.runsecure.hkdfguard.abstractions;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ArrayUtilityTest {
    @Test
    void isNullOrEmpty_Bytes_WithAllZeroEmptyOrNull_ReturnsTrue() {
        assertTrue(ArrayUtility.isNullOrEmpty(new byte[16]));
        assertTrue(ArrayUtility.isNullOrEmpty(new byte[0]));
        assertTrue(ArrayUtility.isNullOrEmpty((byte[]) null));
    }

    @Test
    void isNullOrEmpty_Bytes_WithNonZeroByte_ReturnsFalse() {
        var bytes = new byte[16];
        bytes[10] = 1;

        assertFalse(ArrayUtility.isNullOrEmpty(bytes));
    }

    @Test
    void isNullOrEmpty_Chars_WithAllZeroEmptyOrNull_ReturnsTrue() {
        assertTrue(ArrayUtility.isNullOrEmpty(new char[16]));
        assertTrue(ArrayUtility.isNullOrEmpty(new char[0]));
        assertTrue(ArrayUtility.isNullOrEmpty((char[]) null));
    }

    @Test
    void isNullOrEmpty_Chars_WithNonZeroChar_ReturnsFalse() {
        var chars = new char[16];
        chars[3] = 'a';

        assertFalse(ArrayUtility.isNullOrEmpty(chars));
    }

    @Test
    void isNullOrEmpty_WithTheOnlyNonZeroAtTheEnd_ReturnsFalseForBothOverloads() {
        var bytes = new byte[64];
        bytes[63] = 1;
        var chars = new char[64];
        chars[63] = 'Ā';

        assertFalse(ArrayUtility.isNullOrEmpty(bytes));
        assertFalse(ArrayUtility.isNullOrEmpty(chars));
    }

    @Test
    void zeroMemory_ClearsEveryByteAndChar() {
        var bytes = new byte[] {1, 2, 3, 4, 5};
        var chars = "hello".toCharArray();

        ArrayUtility.zeroMemory(bytes);
        ArrayUtility.zeroMemory(chars);

        assertArrayEquals(new byte[5], bytes);
        assertArrayEquals(new char[5], chars);
    }

    @Test
    void zeroMemory_ARange_ClearsOnlyThatRange() {
        var bytes = new byte[] {1, 2, 3, 4, 5};

        ArrayUtility.zeroMemory(bytes, 1, 3);

        assertArrayEquals(new byte[] {1, 0, 0, 4, 5}, bytes);
    }

    @Test
    void zeroMemory_WithEmptyOrNull_DoesNotThrow() {
        assertDoesNotThrow(() -> ArrayUtility.zeroMemory(new byte[0]));
        assertDoesNotThrow(() -> ArrayUtility.zeroMemory(new char[0]));
        assertDoesNotThrow(() -> ArrayUtility.zeroMemory((byte[]) null));
        assertDoesNotThrow(() -> ArrayUtility.zeroMemory((char[]) null));
    }
}
