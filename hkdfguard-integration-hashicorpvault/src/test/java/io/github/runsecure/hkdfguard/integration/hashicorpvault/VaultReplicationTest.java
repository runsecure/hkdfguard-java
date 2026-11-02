package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/** vault-client-go's replication_consistency tests. */
class VaultReplicationTest {
    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "v1:my-cluster:12345:54321:|",
        "v1:my-cluster:12345:54321:1B9144F5EC067A2A6D6099F16418A3AFD2E5CDA5C9EC318C92D00ED8DD8207E4|my-hmac-key"})
    void parse_ReadsTheState_VerifyingAnHmac(String raw, String hmacKey) {
        var state = VaultReplicationState.parse(encode(raw), hmacKey == null ? null : hmacKey.getBytes(StandardCharsets.UTF_8));

        assertEquals(new VaultReplicationState("my-cluster", 12345, 54321), state);
    }

    @Test
    void parse_ReadsIndexesAsUnsigned() {
        assertEquals(-1L, VaultReplicationState.parse(encode("v1:c:18446744073709551615:0:")).localIndex());
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "v1:my-cluster:12345:54321:1B9144F5EC067A2A6D6099F16418A3AFD2E5CDA5C9EC318C92D00ED8DD8207E4|bad-key",
        "bad-format|", "v1:my-cluster:12345:54321:not-hex|", "v2:my-cluster:1:2:|", "v1::1:2:|", "v1:c:x:2:|", "v1:c:1:-2:|",
        "v1:c:+1:2:|", "v1:c:1:|", "v1:c:18446744073709551616:0:|"})
    void parse_RefusesWhatIsntAState(String raw, String hmacKey) {
        assertThrows(IllegalArgumentException.class,
                () -> VaultReplicationState.parse(encode(raw), hmacKey == null ? null : hmacKey.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void parse_RefusesWhatIsntBase64() {
        assertThrows(IllegalArgumentException.class, () -> VaultReplicationState.parse("not base64!"));
        assertThrows(NullPointerException.class, () -> VaultReplicationState.parse(null));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "|v1:cid:1:0:|v1:cid:1:0:",
        "v1:cid:1:0:|v1:cid:2:0:|v1:cid:2:0:",
        "v1:cid:2:0:|v1:cid:1:0:|v1:cid:2:0:",
        "v1:cid:1:0:|v1:cid:0:1:|v1:cid:0:1:,v1:cid:1:0:",
        "v1:cid:0:1:|v1:cid:1:0:|v1:cid:0:1:,v1:cid:1:0:",
        "v1:cid:0:1:,v1:cid:1:0:|v1:cid:2:0:|v1:cid:0:1:,v1:cid:2:0:",
        "v1:cid:0:1:,v1:cid:1:0:|v1:cid:2:1:|v1:cid:2:1:",
        "v1:a:1:0:,v1:a:2:0:,v1:a:3:0:|v1:a:0:0:|v1:a:0:0:",
        "v1:other:9:9:|v1:cid:1:0:|v1:cid:1:0:",
        "garbage|v1:cid:1:0:|v1:cid:1:0:"})
    void merge_KeepsTheNewestStates(String oldStates, String newState, String expected) {
        var old = oldStates == null ? List.<String>of() : Arrays.stream(oldStates.split(",")).map(VaultReplicationTest::encode).toList();

        var merged = VaultReplication.mergeReplicationStates(old, encode(newState));

        // Sorted by their encoded form, as Vault's own client sorts them.
        assertEquals(Arrays.stream(expected.split(",")).map(VaultReplicationTest::encode).sorted().toList(), merged);
    }

    @Test
    void recordAndRequire_CarryAStateFromAResponseToARequest() {
        var recorded = new AtomicReference<>("unset");
        var record = VaultReplication.recordReplicationState(recorded::set);
        var request = HttpRequest.newBuilder(URI.create("https://vault.test/v1/a")).build();

        record.onResponse(request, 200, HttpHeaders.of(Map.of(), (a, b) -> true));
        assertNull(recorded.get());

        record.onResponse(request, 200, HttpHeaders.of(Map.of("X-Vault-Index", List.of("state-1")), (a, b) -> true));
        var builder = HttpRequest.newBuilder(URI.create("https://vault.test/v1/b"));
        VaultReplication.requireReplicationStates(recorded.get(), "state-2").onRequest(builder);

        assertEquals("state-1", recorded.get());
        assertEquals(List.of("state-1", "state-2"), builder.build().headers().allValues("X-Vault-Index"));
    }

    @Test
    void theCache_IgnoresResponsesWithoutAState_AndCopiesAreIndependent() {
        var cache = new VaultReplication.StateCache(List.of());
        cache.record(HttpHeaders.of(Map.of("X-Vault-Index", List.of("")), (a, b) -> true));
        cache.record(HttpHeaders.of(Map.of(), (a, b) -> true));
        assertTrue(cache.snapshot().isEmpty());

        cache.record(HttpHeaders.of(Map.of("X-Vault-Index", List.of(encode("v1:c:1:0:"))), (a, b) -> true));
        var copy = cache.copy();
        cache.record(HttpHeaders.of(Map.of("X-Vault-Index", List.of(encode("v1:c:2:0:"))), (a, b) -> true));

        assertEquals(List.of(encode("v1:c:2:0:")), cache.snapshot());
        assertEquals(List.of(encode("v1:c:1:0:")), copy.snapshot());
    }

    private static String encode(String s) {
        return Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }
}
