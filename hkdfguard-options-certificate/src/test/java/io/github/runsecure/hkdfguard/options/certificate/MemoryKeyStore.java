package io.github.runsecure.hkdfguard.options.certificate;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreSpi;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * An in-memory KeyStore that stands in for an operating system store: its entries are the tests',
 * a key is handed over without a password as SunMSCAPI hands one over, and every key asked for is
 * recorded, so a test can check only the chosen certificate's key ever left the "store".
 */
final class MemoryKeyStore extends KeyStoreSpi {
    record Entry(X509Certificate[] chain, PrivateKey key) {
    }

    private final Map<String, Entry> entries = new LinkedHashMap<>();
    final List<String> keysRequested = new ArrayList<>();

    static MemoryKeyStore of(Entry... entries) {
        var store = new MemoryKeyStore();
        for (var i = 0; i < entries.length; i++)
            store.entries.put("entry-" + i, entries[i]);
        return store;
    }

    KeyStore keyStore() {
        try {
            var keyStore = new KeyStore(this, new Provider("HkdfGuardTest", "1", "In-memory stores for tests") {
                private static final long serialVersionUID = 1L;
            }, "Memory") {
            };
            keyStore.load(null, null);
            return keyStore;
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public Key engineGetKey(String alias, char[] password) {
        keysRequested.add(alias);
        var entry = entries.get(alias);
        return entry == null ? null : entry.key();
    }

    @Override
    public Certificate[] engineGetCertificateChain(String alias) {
        var entry = entries.get(alias);
        return entry == null ? null : entry.chain().clone();
    }

    @Override
    public Certificate engineGetCertificate(String alias) {
        var entry = entries.get(alias);
        return entry == null ? null : entry.chain()[0];
    }

    @Override
    public Date engineGetCreationDate(String alias) {
        return new Date();
    }

    @Override
    public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain) {
        throw new UnsupportedOperationException("The loader never writes to a store.");
    }

    @Override
    public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) {
        throw new UnsupportedOperationException("The loader never writes to a store.");
    }

    @Override
    public void engineSetCertificateEntry(String alias, Certificate cert) {
        throw new UnsupportedOperationException("The loader never writes to a store.");
    }

    @Override
    public void engineDeleteEntry(String alias) {
        throw new UnsupportedOperationException("The loader never writes to a store.");
    }

    @Override
    public Enumeration<String> engineAliases() {
        return Collections.enumeration(new ArrayList<>(entries.keySet()));
    }

    @Override
    public boolean engineContainsAlias(String alias) {
        return entries.containsKey(alias);
    }

    @Override
    public int engineSize() {
        return entries.size();
    }

    @Override
    public boolean engineIsKeyEntry(String alias) {
        var entry = entries.get(alias);
        return entry != null && entry.key() != null;
    }

    @Override
    public boolean engineIsCertificateEntry(String alias) {
        var entry = entries.get(alias);
        return entry != null && entry.key() == null;
    }

    @Override
    public String engineGetCertificateAlias(Certificate cert) {
        return null;
    }

    @Override
    public void engineStore(OutputStream stream, char[] password) {
        throw new UnsupportedOperationException("The loader never writes to a store.");
    }

    @Override
    public void engineLoad(InputStream stream, char[] password) {
    }
}
