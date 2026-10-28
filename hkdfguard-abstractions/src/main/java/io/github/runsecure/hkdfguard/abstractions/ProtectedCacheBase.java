package io.github.runsecure.hkdfguard.abstractions;

import io.github.runsecure.hkdfguard.diagnostics.HkdfGuardTelemetry;
import io.github.runsecure.hkdfguard.diagnostics.SpanNames;
import io.github.runsecure.hkdfguard.diagnostics.AttributeNames;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import java.nio.charset.StandardCharsets;
import java.util.NoSuchElementException;
import java.util.Objects;
import java.util.OptionalInt;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Shared {@link ProtectedReadOnlyCache} plumbing for every cache in this library: a
 * {@link KeyRing} to encrypt and decrypt through, a concurrent map of encrypted entries keyed by
 * name, and the encrypt/decrypt/telemetry logic every concrete cache needs. decrypt and
 * findMaxDecryptedLength fall back to {@link #tryPopulate} on a miss before giving up - the default
 * implementation here returns false (nothing to pull from), but a subclass backed by an external
 * source (e.g. a remote secret store) overrides it to fetch the plaintext value and encrypt it in
 * on demand, so nothing here ever holds plaintext beyond the duration of a single call.
 * <p>
 * <b>Keys come from the ring, so the cache follows rotation.</b> Every value is encrypted under the
 * ring's current key at the moment it is stored, and its entry records that key's version. Decrypt
 * uses exactly that version, so values stored before a rotation still decrypt while new values use
 * the new key. The cache never owns or closes keys; the ring does.
 * <p>
 * <b>Every entry is bound to its name.</b> Each value is encrypted with Additional Authenticated
 * Data derived from the name it is stored under (see {@link #aadFor}), and decrypted with the AAD
 * of the name it is looked up by. A ciphertext that ends up under any other name fails
 * authentication rather than decrypting as that name's value.
 * <p>
 * Names are matched ignoring ASCII case only (see {@link #canonicalName}): "Item" and "ITEM" are
 * one entry, but "café" and "CAFÉ" are two. The AAD follows exactly the same rule, so every
 * spelling that reaches an entry also authenticates against it - the same case rule
 * {@link ProtectedConfigurationPurpose} uses.
 */
public abstract class ProtectedCacheBase implements ProtectedReadOnlyCache {
    /** The prefix of every cache entry's AAD, keeping it distinct from any other purpose. */
    public static final String AAD_PREFIX = "HkdfGuard.Cache:";

    private static final AttributeKey<String> NAME = AttributeKey.stringKey(AttributeNames.NAME);

    private final KeyRing keyRing;

    // Keyed by canonicalName, so lookups match exactly the names whose AAD they produce.
    private final ConcurrentHashMap<String, KeyTrackingValue> data = new ConcurrentHashMap<>();

    protected ProtectedCacheBase(KeyRing keyRing) {
        this.keyRing = Objects.requireNonNull(keyRing, "keyRing");
    }

    /**
     * The Additional Authenticated Data a value stored under {@code name} is bound to: the UTF-8
     * bytes of {@link #AAD_PREFIX} + name, with ASCII a-z upper-cased.
     *
     * @throws NullPointerException     name is null
     * @throws IllegalArgumentException name is not valid UTF-16 (an unpaired surrogate)
     */
    public static byte[] aadFor(String name) {
        Objects.requireNonNull(name, "name");
        var nameBytes = Utf8Utility.encodeStrict(name);
        var prefix = AAD_PREFIX.getBytes(StandardCharsets.US_ASCII);

        var aad = new byte[prefix.length + nameBytes.length];
        System.arraycopy(prefix, 0, aad, 0, prefix.length);
        // Upper-casing at the byte level is exact: in UTF-8, bytes 0x61-0x7A only ever encode
        // those ASCII letters.
        for (var i = 0; i < nameBytes.length; i++) {
            var b = nameBytes[i];
            aad[prefix.length + i] = b >= 'a' && b <= 'z' ? (byte) (b - ('a' - 'A')) : b;
        }
        return aad;
    }

    /**
     * How names are matched: two names are the same entry exactly when their canonical names are
     * equal - ASCII a-z upper-cased, every other character compared as-is.
     *
     * @throws NullPointerException name is null
     */
    protected static String canonicalName(String name) {
        Objects.requireNonNull(name, "name");
        for (var i = 0; i < name.length(); i++) {
            var c = name.charAt(i);
            if (c >= 'a' && c <= 'z') {
                var chars = name.toCharArray();
                for (var j = i; j < chars.length; j++)
                    if (chars[j] >= 'a' && chars[j] <= 'z')
                        chars[j] = (char) (chars[j] - ('a' - 'A'));
                return new String(chars);
            }
        }
        return name;
    }

    /**
     * Called when name isn't already stored, before decrypt/findMaxDecryptedLength give up. The
     * default implementation does nothing - override to pull a value in from an external source and
     * store it (via {@link #encrypt}/{@link #encryptChars} for this same name, then
     * {@link #putEntry}) before returning true.
     *
     * @return true if name was populated as a result of this call
     */
    protected boolean tryPopulate(String name) {
        return false;
    }

    /** Stores an entry from {@link #encrypt}/{@link #encryptChars} for this same name, replacing any. */
    protected final void putEntry(String name, KeyTrackingValue entry) {
        data.put(canonicalName(name), Objects.requireNonNull(entry, "entry"));
    }

    /**
     * Stores an entry from {@link #encrypt}/{@link #encryptChars} for this same name, unless one is
     * already stored.
     *
     * @return true if it was stored
     */
    protected final boolean putEntryIfAbsent(String name, KeyTrackingValue entry) {
        return data.putIfAbsent(canonicalName(name), Objects.requireNonNull(entry, "entry")) == null;
    }

    /** The entry stored under name, or null - without falling back to {@link #tryPopulate}. */
    protected final KeyTrackingValue getEntry(String name) {
        return data.get(canonicalName(name));
    }

    /** Removes the entry stored under name; true if there was one. */
    protected final boolean removeEntry(String name) {
        return data.remove(canonicalName(name)) != null;
    }

    /**
     * {@inheritDoc}
     *
     * @throws NoSuchElementException the entry's key version is no longer in the ring
     */
    @Override
    public int decrypt(String name, byte[] result) {
        try (var op = HkdfGuardTelemetry.ROOT.startSpan(SpanNames.Cache.DECRYPT)) {
            if (HkdfGuardTelemetry.ROOT.isSensitiveLoggingEnabled())
                HkdfGuardTelemetry.ROOT.logSensitiveOperation(op.span(), SpanNames.Cache.DECRYPT, Attributes.of(NAME, name));

            try {
                var entry = findEntry(name);
                if (entry == null)
                    return 0;

                var key = keyRing.get(entry.keyVersion());
                return key.decrypt(entry.value(), aadFor(name), result);
            } catch (RuntimeException e) {
                op.recordException(e);
                throw e;
            }
        }
    }

    /**
     * {@inheritDoc}
     *
     * @throws NoSuchElementException the entry's key version is no longer in the ring
     */
    @Override
    public int decrypt(String name, char[] result) {
        try (var op = HkdfGuardTelemetry.ROOT.startSpan(SpanNames.Cache.DECRYPT)) {
            if (HkdfGuardTelemetry.ROOT.isSensitiveLoggingEnabled())
                HkdfGuardTelemetry.ROOT.logSensitiveOperation(op.span(), SpanNames.Cache.DECRYPT, Attributes.of(NAME, name));

            try {
                var entry = findEntry(name);
                if (entry == null)
                    return 0;

                var key = keyRing.get(entry.keyVersion());
                var aad = aadFor(name);

                // AEAD ciphertext is always at least as long as the plaintext it encloses, so the
                // entry's length is a safe upper bound for the decrypted UTF-8 byte count.
                return Utf8Utility.decodeWritten(entry.value().length, bytes -> key.decrypt(entry.value(), aad, bytes), result);
            } catch (RuntimeException e) {
                op.recordException(e);
                throw e;
            }
        }
    }

    @Override
    public OptionalInt findMaxDecryptedLength(String name) {
        var entry = findEntry(name);
        return entry == null ? OptionalInt.empty() : OptionalInt.of(entry.value().length);
    }

    private KeyTrackingValue findEntry(String name) {
        var entry = getEntry(name);
        if (entry != null)
            return entry;

        return tryPopulate(name) ? getEntry(name) : null;
    }

    /**
     * Encrypts plaintext under the ring's current key, bound to {@code name} - store the result
     * under that same name. The entry records the key version, so it keeps decrypting after the
     * ring rotates. plaintext is zeroed as a side effect, on every path.
     *
     * @throws IllegalArgumentException plaintext is empty - decrypt reports a missing name as 0
     *                                  bytes, so an empty value would be indistinguishable from no
     *                                  value - or name is not valid UTF-16
     * @throws IllegalStateException    the ring has no key yet
     */
    protected final KeyTrackingValue encrypt(String name, byte[] plaintext) {
        Objects.requireNonNull(plaintext, "plaintext");
        if (plaintext.length == 0)
            throw new IllegalArgumentException("An empty value cannot be cached: decrypt reports a missing name as 0 bytes.");

        try {
            var aad = aadFor(name);

            // Resolved on every call, so a value stored after a rotation uses the new key.
            var current = keyRing.getCurrent();
            return new KeyTrackingValue(current.version(), current.key().encrypt(plaintext, aad));
        } finally {
            // Normally already done by the key; this covers a failure before encrypting.
            ArrayUtility.zeroMemory(plaintext);
        }
    }

    /**
     * Encrypts plaintext (as UTF-8 bytes) under the ring's current key, bound to {@code name} -
     * store the result under that same name. plaintext is zeroed as a side effect, on every path.
     *
     * @throws IllegalArgumentException plaintext is empty, or name is not valid UTF-16
     * @throws IllegalStateException    the ring has no key yet
     */
    protected final KeyTrackingValue encryptChars(String name, char[] plaintext) {
        Objects.requireNonNull(plaintext, "plaintext");
        byte[] plaintextBytes = null;
        try {
            if (plaintext.length == 0)
                throw new IllegalArgumentException("An empty value cannot be cached: decrypt reports a missing name as 0 bytes.");

            plaintextBytes = Utf8Utility.encode(java.nio.CharBuffer.wrap(plaintext));
            return encrypt(name, plaintextBytes);
        } finally {
            // Zeroed here, not left to whichever key/provider is underneath.
            ArrayUtility.zeroMemory(plaintextBytes);
            ArrayUtility.zeroMemory(plaintext);
        }
    }
}
