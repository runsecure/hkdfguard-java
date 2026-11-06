package io.github.runsecure.hkdfguard.pipeline;

import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import java.util.List;
import java.util.Map;

/** The shared writer over a {@link FakeStore}: readSecret only, so readSecretAsync is the default's. */
final class FakeWriter extends SecretPipelineWriterBase {
    private final FakeStore store;
    boolean closed;

    FakeWriter(PipelineDataProtector protector, List<String> secretNames, FakeStore store) {
        this(protector, secretNames, store, null);
    }

    FakeWriter(PipelineDataProtector protector, List<String> secretNames, FakeStore store, String defaultKey) {
        super(protector, secretNames, FakeStore::isValidName, defaultKey);
        this.store = store;
    }

    @Override
    protected void readSecret(String name, List<SecretRequest> requests, Map<String, String> values) {
        store.reads.add(name);
        var failure = store.failWith;
        if (failure != null)
            throw failure;
        var secret = store.secrets.get(name);
        if (secret != null)
            protectSecret(secret.clone(), secret.length, requests, values);
    }

    @Override
    public void close() {
        closed = true;
    }
}
