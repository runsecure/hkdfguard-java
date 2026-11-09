package io.github.runsecure.hkdfguard.pipeline;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/** A store of secret values by name, as UTF-8 bytes; names are ASCII letters, digits, hyphens and '/'. */
final class FakeStore {
    final Map<String, byte[]> secrets = new ConcurrentHashMap<>();

    final List<String> reads = new CopyOnWriteArrayList<>();

    volatile RuntimeException failWith;

    static boolean isValidName(String name) {
        for (var i = 0; i < name.length(); i++) {
            var c = name.charAt(i);
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '/'))
                return false;
        }
        return true;
    }

    void set(String name, String value) {
        secrets.put(name, value.getBytes(StandardCharsets.UTF_8));
    }
}
