package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import java.net.http.HttpHeaders;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;
import java.util.function.Consumer;

/**
 * Read-your-writes across a Vault Enterprise cluster by hand - what
 * {@link VaultClientOptions#enforceReadYourWritesConsistency()} does for every request: record the
 * state a write's response carries, then require it of a later read; see
 * https://developer.hashicorp.com/vault/docs/enterprise/consistency#conditional-forwarding-performance-standbys-only.
 */
public final class VaultReplication {
    static final String INDEX_HEADER = "X-Vault-Index";

    private VaultReplication() {
    }

    /** A response callback handing record the response's replication state (X-Vault-Index), or null if it has none. */
    public static VaultResponseCallback recordReplicationState(Consumer<String> record) {
        Objects.requireNonNull(record, "record");
        return (request, status, headers) -> record.accept(headers.firstValue(INDEX_HEADER).orElse(null));
    }

    /** A request callback requiring states (X-Vault-Index) of the node that answers - states recorded with {@link #recordReplicationState}. */
    public static VaultRequestCallback requireReplicationStates(String... states) {
        Objects.requireNonNull(states, "states");
        var copy = List.of(states);
        return request -> {
            for (var state : copy)
                request.header(INDEX_HEADER, state);
        };
    }

    /**
     * The states to require after seeing newState, given those required so far: each old state newer
     * than newState kept, newState kept if newer than any - both when neither is newer - sorted, with
     * no duplicates. Just newState when there are no old states or more than two, or when any can't
     * be compared with it (unparsable, or another cluster's).
     */
    public static List<String> mergeReplicationStates(List<String> oldStates, String newState) {
        Objects.requireNonNull(oldStates, "oldStates");
        Objects.requireNonNull(newState, "newState");
        if (oldStates.isEmpty() || oldStates.size() > 2)
            return List.of(newState);

        var merged = new ArrayList<String>();
        for (var old : oldStates) {
            int comparison;
            try {
                comparison = compare(old, newState);
            } catch (IllegalArgumentException e) {
                return List.of(newState);
            }

            switch (comparison) {
                case 1 -> merged.add(old);
                case -1 -> merged.add(newState);
                default -> {
                    merged.add(old);
                    merged.add(newState);
                }
            }
        }

        // strutil.RemoveDuplicates: trimmed, empties dropped, distinct, sorted.
        var distinct = new TreeSet<String>();
        for (var state : merged) {
            var trimmed = state.strip();
            if (!trimmed.isEmpty())
                distinct.add(trimmed);
        }
        return List.copyOf(distinct);
    }

    /**
     * 1 if s1 is newer than s2 or the same, -1 if older, 0 if neither is.
     *
     * @throws IllegalArgumentException either isn't a replication state, or they're different clusters'
     */
    static int compare(String s1, String s2) {
        var r1 = VaultReplicationState.parse(s1);
        var r2 = VaultReplicationState.parse(s2);
        if (!r1.cluster().equals(r2.cluster()))
            throw new IllegalArgumentException("Can't compare replication states from different clusters.");

        var local = Long.compareUnsigned(r1.localIndex(), r2.localIndex());
        var replicated = Long.compareUnsigned(r1.replicatedIndex(), r2.replicatedIndex());
        if (local >= 0 && replicated >= 0)
            return 1;
        if (local <= 0 && replicated <= 0)
            return -1;
        return 0;
    }

    /**
     * The replication states a client has seen, for
     * {@link VaultClientOptions#enforceReadYourWritesConsistency()}: at most two, as
     * {@link #mergeReplicationStates} keeps them.
     */
    static final class StateCache {
        private List<String> states;

        StateCache(List<String> states) {
            this.states = states;
        }

        /** Merges the state headers carry, if any, into those seen. */
        void record(HttpHeaders headers) {
            var state = headers.firstValue(INDEX_HEADER).orElse("");
            if (state.isEmpty())
                return;

            synchronized (this) {
                states = mergeReplicationStates(states, state);
            }
        }

        /** The states seen so far, to require of the next request. */
        synchronized List<String> snapshot() {
            return states;
        }

        StateCache copy() {
            return new StateCache(snapshot());
        }
    }
}
