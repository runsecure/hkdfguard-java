package io.github.runsecure.hkdfguard.abstractions;

/**
 * One data encryption key (DEK): AEAD-encrypts and decrypts byte payloads under it, optionally
 * bound to Additional Authenticated Data.
 * <p>
 * <b>Encrypt consumes its plaintext.</b> The {@code plaintext} array is zeroed before encrypt
 * returns, and also when it throws, so a secret handed in is never left behind in the caller's
 * buffer. Callers that still need the value afterwards must pass a copy. Decrypt never modifies
 * its ciphertext.
 */
public interface DataEncryptionKey {
    /**
     * Encrypts plaintext under this key.
     *
     * @param plaintext the bytes to protect; zeroed before this returns or throws - pass a copy if
     *                  you still need them
     * @return the ciphertext, ready to be stored
     */
    byte[] encrypt(byte[] plaintext);

    /**
     * Encrypts plaintext under this key, bound to {@code aad}.
     *
     * @param plaintext the bytes to protect; zeroed before this returns or throws
     * @param aad       Additional Authenticated Data; decrypt must supply the same bytes
     * @return the ciphertext, ready to be stored
     */
    byte[] encrypt(byte[] plaintext, byte[] aad);

    /**
     * Decrypts and authenticates ciphertext produced by {@link #encrypt(byte[])}.
     *
     * @param ciphertext the ciphertext; not modified
     * @param result     receives the plaintext; the caller owns it and should zero it once done
     * @return the number of bytes written to result
     */
    int decrypt(byte[] ciphertext, byte[] result);

    /**
     * Decrypts and authenticates ciphertext produced by {@link #encrypt(byte[], byte[])} with the
     * same {@code aad}.
     *
     * @param ciphertext the ciphertext; not modified
     * @param aad        the Additional Authenticated Data it was encrypted with
     * @param result     receives the plaintext; the caller owns it and should zero it once done
     * @return the number of bytes written to result
     */
    int decrypt(byte[] ciphertext, byte[] aad, byte[] result);
}
