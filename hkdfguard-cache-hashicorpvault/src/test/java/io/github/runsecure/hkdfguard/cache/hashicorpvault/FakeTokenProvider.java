package io.github.runsecure.hkdfguard.cache.hashicorpvault;

import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntFunction;

/**
 * A token provider that counts its calls, and can hand out any token or fail. Each token
 * {@link #next} gives is protected by {@link #protector}, as a real provider's is, unless the
 * provider is unprotected.
 */
final class FakeTokenProvider implements VaultTokenProvider {
    private final AtomicInteger calls = new AtomicInteger();
    private final boolean unprotected;

    /** Gives the token for call number n (from 1). */
    volatile IntFunction<CompletableFuture<String>> next = call -> CompletableFuture.completedFuture(FakeVault.TOKEN);

    /** Protects every token handed out; the tests set it to the cache's own token protector. */
    volatile DataProtector protector;

    /** The future next gave last, before protection. */
    volatile CompletableFuture<String> lastGiven;

    FakeTokenProvider() {
        this(false);
    }

    /** @param unprotected hand tokens out exactly as next gives them, as a provider that doesn't protect them would */
    FakeTokenProvider(boolean unprotected) {
        this.unprotected = unprotected;
    }

    static FakeTokenProvider giving(String token) {
        var provider = new FakeTokenProvider();
        provider.next = call -> CompletableFuture.completedFuture(token);
        return provider;
    }

    int calls() {
        return calls.get();
    }

    @Override
    public CompletableFuture<String> getTokenAsync() {
        var given = next.apply(calls.incrementAndGet());
        lastGiven = given;
        var protecting = protector;
        return unprotected || protecting == null ? given : given.thenApply(protecting::encrypt);
    }
}
