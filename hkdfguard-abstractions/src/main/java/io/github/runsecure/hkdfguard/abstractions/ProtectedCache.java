package io.github.runsecure.hkdfguard.abstractions;

/**
 * Read/write surface of a highly concurrent name -&gt; encrypted-value cache. add/addOrUpdate
 * protect and store plaintext under a name; the read surface is inherited from
 * {@link ProtectedReadOnlyCache}. Nothing here ever holds plaintext beyond the duration of a single
 * call - only the encrypted bytes are retained.
 */
public interface ProtectedCache extends ProtectedReadOnlyCache {
    /**
     * Encrypts plaintext and stores it under name.
     *
     * @param plaintext the plaintext to protect - zeroed as a side effect of encrypting it
     * @throws IllegalArgumentException a value is already stored under this name
     */
    void add(String name, byte[] plaintext);

    /**
     * Encrypts plaintext (as UTF-8 bytes) and stores it under name.
     *
     * @param plaintext the plaintext to protect - zeroed as a side effect of encrypting it
     * @throws IllegalArgumentException a value is already stored under this name
     */
    void add(String name, char[] plaintext);

    /**
     * Encrypts plaintext and stores it under name, replacing any value already stored there.
     *
     * @param plaintext the plaintext to protect - zeroed as a side effect of encrypting it
     */
    void addOrUpdate(String name, byte[] plaintext);

    /**
     * Encrypts plaintext (as UTF-8 bytes) and stores it under name, replacing any value already
     * stored there.
     *
     * @param plaintext the plaintext to protect - zeroed as a side effect of encrypting it
     */
    void addOrUpdate(String name, char[] plaintext);
}
