package io.github.runsecure.hkdfguard.keywrapping.hashicorpvault;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntFunction;

/**
 * A token source that counts its calls, and can hand out any token or fail. It copies as much of the
 * token as fits and reports its whole length, as a source with a token too long would.
 */
final class FakeTokenSource implements VaultTokenSource {
    private final AtomicInteger calls = new AtomicInteger();
    private final List<char[]> destinations = Collections.synchronizedList(new ArrayList<>());

    /** Gives the token for call number n (from 1). */
    volatile IntFunction<CompletableFuture<String>> next = call -> CompletableFuture.completedFuture(FakeTransit.TOKEN);

    /** The future copyTokenAsync returned last. */
    volatile CompletableFuture<Integer> lastReturned;

    static FakeTokenSource giving(String token) {
        var source = new FakeTokenSource();
        source.next = call -> CompletableFuture.completedFuture(token);
        return source;
    }

    int calls() {
        return calls.get();
    }

    /** Every destination the wrapper handed over, to check what became of it. */
    List<char[]> destinations() {
        synchronized (destinations) {
            return List.copyOf(destinations);
        }
    }

    @Override
    public CompletableFuture<Integer> copyTokenAsync(char[] destination) {
        destinations.add(destination);
        var returned = next.apply(calls.incrementAndGet()).thenApply(token -> {
            token.getChars(0, Math.min(token.length(), destination.length), destination, 0);
            return token.length();
        });
        lastReturned = returned;
        return returned;
    }
}
