package io.github.runsecure.hkdfguard.options.certificate;

import io.github.runsecure.hkdfguard.abstractions.ProtectedReadOnlyCache;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
import java.util.concurrent.CompletableFuture;

/** Passwords by name, as a protected secret source hands them over; it records every buffer it was given. */
final class FakePasswords implements ProtectedReadOnlyCache {
    final Map<String, String> values = new HashMap<>();
    final List<char[]> buffers = new ArrayList<>();
    int reads;
    int asyncReads;

    /** When set, decryptAsync returns this future instead, filling the buffer only when the test says. */
    CompletableFuture<Integer> pendingDecrypt;

    FakePasswords with(String name, String value) {
        values.put(name, value);
        return this;
    }

    @Override
    public int decrypt(String name, byte[] result) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int decrypt(String name, char[] result) {
        reads++;
        buffers.add(result);
        var value = values.get(name);
        if (value == null)
            return 0;
        value.getChars(0, value.length(), result, 0);
        return value.length();
    }

    @Override
    public OptionalInt findMaxDecryptedLength(String name) {
        var value = values.get(name);
        return value == null ? OptionalInt.empty() : OptionalInt.of(value.length());
    }

    @Override
    public CompletableFuture<Integer> decryptAsync(String name, char[] result) {
        asyncReads++;
        if (pendingDecrypt != null) {
            buffers.add(result);
            var value = values.get(name);
            value.getChars(0, value.length(), result, 0);
            return pendingDecrypt;
        }
        reads--;
        var count = decrypt(name, result);
        return CompletableFuture.completedFuture(count);
    }
}
