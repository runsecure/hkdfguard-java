package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import io.github.runsecure.hkdfguard.abstractions.DataProtector;
import java.time.Duration;
import java.util.function.Consumer;
import org.slf4j.Logger;

/** A client over a {@link FakeVault}, its token protector, and the fake's token already protected and set. */
record TestClient(VaultClient client, FakeVault vault, DataProtector protector) implements AutoCloseable {
    static TestClient create() {
        return create(null, true, null);
    }

    static TestClient create(Consumer<VaultClientOptions.Builder> configure) {
        return create(configure, true, null);
    }

    static TestClient create(Consumer<VaultClientOptions.Builder> configure, boolean withToken, Logger logger) {
        var vault = new FakeVault();
        var protector = TestRings.protector();
        var options = VaultClientOptions.builder()
                .address(vault.address())
                // No waits between retries: tests that meet a 5xx stay quick.
                .retry(VaultRetryOptions.builder().retryWaitMin(Duration.ZERO).retryWaitMax(Duration.ZERO).build());
        if (withToken)
            options.token(StaticVaultToken.protect(protector, FakeVault.TOKEN));
        if (configure != null)
            configure.accept(options);
        try {
            return new TestClient(new VaultClient(protector, options.build(), logger), vault, protector);
        } catch (RuntimeException e) {
            vault.close();
            throw e;
        }
    }

    /** The token protectedToken holds, decrypted with this client's protector. */
    String decrypt(StaticVaultToken protectedToken) {
        return TestRings.decrypt(protector, protectedToken.toString());
    }

    @Override
    public void close() {
        client.close();
        vault.close();
    }
}
