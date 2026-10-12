package io.github.runsecure.hkdfguard.abstractions;

import java.lang.ref.Reference;
import java.util.Arrays;

/**
 * Helpers for buffers holding secrets.
 * <p>
 * Unlike .NET, the JVM offers no pinned or stack allocation for Java arrays: a compacting
 * collector may move an array and leave its old contents behind until that memory is reused.
 * Zeroing therefore erases the live copy of a secret, never every copy the heap may once have
 * held. The library still zeroes every buffer it owns as soon as it's done with it, which bounds
 * how long a secret stays reachable and keeps it out of heap dumps taken afterwards.
 */
public final class ArrayUtility {
    private ArrayUtility() {
    }

    /**
     * True if the array is null, empty, or every byte is zero. Runs in time that depends only on
     * the length, never on the contents, so it is safe to call on key material.
     */
    public static boolean isNullOrEmpty(byte[] input) {
        if (input == null)
            return true;

        var accumulator = 0;
        for (var b : input)
            accumulator |= b;
        return accumulator == 0;
    }

    /**
     * True if the array is null, empty, or every char is '\0'. Runs in time that depends only on
     * the length, never on the contents.
     */
    public static boolean isNullOrEmpty(char[] input) {
        if (input == null)
            return true;

        var accumulator = 0;
        for (var c : input)
            accumulator |= c;
        return accumulator == 0;
    }

    /** Zeroes every byte of the array; a null array is ignored. */
    public static void zeroMemory(byte[] input) {
        if (input == null)
            return;

        Arrays.fill(input, (byte) 0);
        // Keeps the array reachable until the stores are done, so they can't be elided as dead.
        Reference.reachabilityFence(input);
    }

    /** Zeroes bytes {@code [from, to)} of the array. */
    public static void zeroMemory(byte[] input, int from, int to) {
        Arrays.fill(input, from, to, (byte) 0);
        Reference.reachabilityFence(input);
    }

    /** Zeroes every char of the array; a null array is ignored. */
    public static void zeroMemory(char[] input) {
        if (input == null)
            return;

        Arrays.fill(input, '\0');
        Reference.reachabilityFence(input);
    }
}
