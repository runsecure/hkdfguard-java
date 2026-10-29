package io.github.runsecure.hkdfguard.cache;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.KeyTrackingValue;
import io.github.runsecure.hkdfguard.abstractions.Utf8Utility;
import java.util.HashMap;
import java.util.Map;

/**
 * Receives what {@link RemoteSecretCache#fetch} read, and encrypts each value at once, bound to its
 * own name within the secret being fetched - nothing else can be stored through it, and it refuses
 * every call once that fetch has returned (or been cancelled). Set the secret's whole value at most
 * once, and each key at most once; an empty value counts as none. Thread-safe, so a fetch may hand
 * values over from whichever thread its client answers on.
 */
public final class SecretValueSink {
    private final RemoteSecretCache.Store store;
    private final String secretEntryName;
    private final Map<String, KeyTrackingValue> values = new HashMap<>();
    private boolean closed;

    SecretValueSink(RemoteSecretCache.Store store, String secretEntryName) {
        this.store = store;
        this.secretEntryName = secretEntryName;
    }

    /**
     * Encrypts plaintext as the secret's whole value. plaintext is zeroed as a side effect.
     *
     * @throws IllegalStateException the value was already set, or the fetch has returned
     */
    public synchronized void setBytes(byte[] plaintext) {
        set(secretEntryName, plaintext);
    }

    /**
     * Encrypts text's UTF-8 bytes as the secret's whole value. The bytes are zeroed once encrypted;
     * text itself is read-only and is left as it is - pass a {@code CharBuffer.wrap(char[])} to keep
     * a secret out of String, and clear the array afterwards.
     *
     * @throws IllegalStateException the value was already set, or the fetch has returned
     */
    public synchronized void setText(CharSequence text) {
        ensureUnset(secretEntryName);
        set(secretEntryName, Utf8Utility.encode(text));
    }

    /**
     * Encrypts plaintext as the value of one key the secret holds - looked up as "name#key".
     * plaintext is zeroed as a side effect.
     *
     * @throws IllegalArgumentException key isn't one a name can hold (see
     *                                  {@link RemoteSecretCache#isValidKey})
     * @throws IllegalStateException    that key was already set, or the fetch has returned
     */
    public synchronized void setKeyBytes(String key, byte[] plaintext) {
        try {
            if (!RemoteSecretCache.isValidKey(key))
                throw new IllegalArgumentException("'" + key + "' isn't a key: 1-" + RemoteSecretCache.MAX_KEY_LENGTH
                        + " printable ASCII characters other than space, '!' and '#'.");

            set(secretEntryName + RemoteSecretCache.KEY_SEPARATOR + RemoteSecretCache.entryName(key), plaintext);
        } finally {
            ArrayUtility.zeroMemory(plaintext);
        }
    }

    /**
     * Encrypts plaintext as the secret's whole value and, when it is a JSON object - such as an AWS
     * Secrets Manager key/value secret - each of its top-level members as a key: a string as its
     * UTF-8 bytes, a number, true or false as its JSON text. A member that is null, an object or an
     * array, or whose name isn't a key a name can hold, is left out. Anything that isn't a JSON
     * object - plain text, an array, malformed JSON - is the whole value only. plaintext is zeroed
     * as a side effect, and every buffer a member was unescaped into is zeroed once encrypted.
     *
     * @throws InvalidSecretDataException the JSON object holds a member name more than once
     * @throws IllegalStateException      the value or a key was already set, or the fetch has
     *                                    returned
     */
    public synchronized void setBytesWithJsonKeys(byte[] plaintext) {
        try {
            SecretJsonKeys.trySetKeys(plaintext, this);
            setBytes(plaintext);
        } finally {
            ArrayUtility.zeroMemory(plaintext);
        }
    }

    /** Refuses every later call, and returns every value set, by the entry name it was encrypted under. */
    synchronized Map<String, KeyTrackingValue> close() {
        closed = true;
        return Map.copyOf(values);
    }

    private void set(String entryName, byte[] plaintext) {
        try {
            ensureUnset(entryName);
            if (plaintext.length > 0)
                values.put(entryName, store.encryptEntry(entryName, plaintext));
        } finally {
            ArrayUtility.zeroMemory(plaintext);
        }
    }

    private void ensureUnset(String entryName) {
        if (closed)
            throw new IllegalStateException("The fetch this value belongs to has already returned.");
        if (values.containsKey(entryName))
            throw new IllegalStateException("A value has already been set for this secret or key.");
    }
}
