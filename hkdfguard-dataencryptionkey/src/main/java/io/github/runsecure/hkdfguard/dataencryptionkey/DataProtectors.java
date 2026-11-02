package io.github.runsecure.hkdfguard.dataencryptionkey;

import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import io.github.runsecure.hkdfguard.abstractions.EncryptedFormatProvider;
import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.abstractions.ProtectedCacheBase;
import java.util.Objects;

/**
 * Creates {@link DataProtector}s over any {@link KeyRing} - an application's own, not only
 * {@link KeyRingImpl}, whose {@link KeyRingImpl#createProtector} comes here with its own format
 * provider. Every protector follows the same rules, whichever ring it is over.
 */
public final class DataProtectors {
    private DataProtectors() {
    }

    /**
     * A protector bound to {@code keyRing}: encrypt resolves the current version on every call, and
     * decrypt the version each formatted value names.
     *
     * @param keyRing        the ring whose keys protect and reveal values
     * @param name           the protector's Additional Authenticated Data on every encrypt/decrypt
     * @param formatProvider formats and parses every value the protector produces
     * @return the protector
     * @throws NullPointerException     an argument is null
     * @throws IllegalArgumentException name is empty - an empty purpose binds nothing - or starts with
     *                                  {@link ProtectedCacheBase#AAD_PREFIX}, whose AADs belong to
     *                                  protected caches alone, or isn't valid UTF-16
     */
    public static DataProtector create(KeyRing keyRing, String name, EncryptedFormatProvider formatProvider) {
        Objects.requireNonNull(keyRing, "keyRing");
        Objects.requireNonNull(name, "name");
        Objects.requireNonNull(formatProvider, "formatProvider");
        if (name.isEmpty())
            throw new IllegalArgumentException("A protector name must not be empty.");
        if (name.startsWith(ProtectedCacheBase.AAD_PREFIX))
            throw new IllegalArgumentException("Protector names starting with '" + ProtectedCacheBase.AAD_PREFIX
                    + "' are reserved for ProtectedCache's entries.");

        return new DataProtectorImpl(name, keyRing, formatProvider);
    }
}
