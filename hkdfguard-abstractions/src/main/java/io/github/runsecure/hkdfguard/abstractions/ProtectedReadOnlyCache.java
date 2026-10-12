package io.github.runsecure.hkdfguard.abstractions;

import java.util.OptionalInt;

/**
 * Read surface of a highly concurrent name -&gt; encrypted-value cache. Names are compared ignoring
 * ASCII case only ("Item" and "ITEM" are the same name; "café" and "CAFÉ" are not), and each value
 * is bound to its name, so a value can only be revealed under the name it was stored for. Decrypt
 * reveals a stored value into a caller-owned buffer, returning 0 for a missing name rather than
 * throwing. Nothing here ever holds plaintext beyond the duration of a single decrypt call.
 */
public interface ProtectedReadOnlyCache {
    /**
     * Decrypts the value stored under name into result.
     *
     * @return the number of bytes written to result, or 0 if no value is stored under name
     */
    int decrypt(String name, byte[] result);

    /**
     * Decrypts the value stored under name into result as UTF-8-decoded characters.
     *
     * @return the number of chars written to result, or 0 if no value is stored under name
     */
    int decrypt(String name, char[] result);

    /**
     * An upper bound on how many bytes or chars decrypt will write for the value stored under
     * name, so a result buffer can be sized without decrypting first; empty if no value is stored
     * under name.
     */
    OptionalInt findMaxDecryptedLength(String name);
}
