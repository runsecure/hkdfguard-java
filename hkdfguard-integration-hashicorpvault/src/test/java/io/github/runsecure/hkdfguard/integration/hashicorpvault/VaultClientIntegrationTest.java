package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import static io.github.runsecure.hkdfguard.integration.hashicorpvault.Futures.assertFailsWith;
import static io.github.runsecure.hkdfguard.integration.hashicorpvault.Futures.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.integration.hashicorpvault.schema.KvV2ReadResponse;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.schema.KvV2WriteRequest;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.schema.TokenCreateRequest;
import java.net.URI;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * The client against a real Vault dev server, which these tests write to - a KV version 2 engine at
 * "secret" (a dev server's default), under hkdfguard-client-test/:
 *
 * <pre>
 * HKDFGUARD_TEST_VAULT_ADDR=http://127.0.0.1:8200 HKDFGUARD_TEST_VAULT_TOKEN=dev-root \
 *   ./mvnw test -pl hkdfguard-integration-hashicorpvault -Dtest=VaultClientIntegrationTest
 * </pre>
 *
 * Without HKDFGUARD_TEST_VAULT_TOKEN, or with an address that isn't loopback, every test here is
 * reported as skipped - never as passed. HKDFGUARD_TEST_VAULT_CACERT is needed only for a server
 * certificate the JDK doesn't trust (a dev server started with -dev-tls).
 */
class VaultClientIntegrationTest {
    private static URI address() {
        var address = System.getenv("HKDFGUARD_TEST_VAULT_ADDR");
        return URI.create(address == null || address.isEmpty() ? "https://127.0.0.1:8200" : address);
    }

    @BeforeEach
    void requireADevServer() {
        var token = System.getenv("HKDFGUARD_TEST_VAULT_TOKEN");
        Assumptions.assumeTrue(token != null && !token.isEmpty(),
                "Set HKDFGUARD_TEST_VAULT_TOKEN (and HKDFGUARD_TEST_VAULT_ADDR) to a Vault dev server's to run Vault client integration tests.");
        Assumptions.assumeTrue(VaultHttp.isLoopback(address().getHost()),
                "The Vault client integration tests write secrets: HKDFGUARD_TEST_VAULT_ADDR must be a dev server on loopback.");
    }

    private static VaultClient create() {
        var protector = TestRings.protector();
        var tls = VaultTlsOptions.builder();
        var ca = System.getenv("HKDFGUARD_TEST_VAULT_CACERT");
        if (ca != null && !ca.isEmpty())
            tls.serverCertificateFile(Path.of(ca));
        return new VaultClient(protector, VaultClientOptions.builder()
                .address(address())
                .token(StaticVaultToken.protect(protector, System.getenv("HKDFGUARD_TEST_VAULT_TOKEN")))
                .tls(tls.build())
                .build());
    }

    private static final VaultRequestOptions SECRET = VaultRequestOptions.builder().mountPath("secret").build();

    @Test
    void health_IsReadWithoutAToken() {
        try (var client = create()) {
            client.clearToken();

            var health = await(client.system().readHealthStatusAsync());

            assertTrue(health.data().get("initialized").asBoolean());
        }
    }

    @Test
    void aSecret_IsWrittenReadListedAndDeleted_ThroughTheGeneratedApi() {
        try (var client = create()) {
            var name = UUID.randomUUID().toString().replace("-", "");
            var path = "hkdfguard-client-test/" + name;

            var written = await(client.secrets().kvV2WriteAsync(path, new KvV2WriteRequest().setData(Map.of("password", "s3cret", "n", 7)), SECRET));
            var read = await(client.secrets().kvV2ReadAsync(path, SECRET));
            var listed = await(client.secrets().kvV2ListAsync("hkdfguard-client-test", SECRET));
            await(client.secrets().kvV2DeleteMetadataAndAllVersionsAsync(path, SECRET));

            assertEquals(1L, written.data().getVersion());
            assertEquals("s3cret", read.data().getData().get("password").asString());
            assertEquals(7, read.data().getData().get("n").asLong());
            assertTrue(listed.data().getKeys().contains(name));
            var e = assertFailsWith(VaultResponseException.class, client.secrets().kvV2ReadAsync(path, SECRET));
            assertTrue(VaultClient.isErrorStatus(e, 404));
        }
    }

    @Test
    void theGenericMethods_ReachAnyPath() {
        try (var client = create()) {
            var path = "secret/data/hkdfguard-client-test/" + UUID.randomUUID().toString().replace("-", "");

            await(client.writeAsync(path, Map.of("data", Map.of("k", "v"))));
            var read = await(client.readAsync(path));
            await(client.deleteAsync(path.replace("/data/", "/metadata/")));

            assertEquals("v", read.data().get("data").member("k").asString());
        }
    }

    @Test
    void aWrappedResponse_IsUnwrappedWithItsProtectedToken() {
        try (var client = create()) {
            var path = "hkdfguard-client-test/" + UUID.randomUUID().toString().replace("-", "");
            await(client.secrets().kvV2WriteAsync(path, new KvV2WriteRequest().setData(Map.of("k", "wrapped")), SECRET));

            var wrapped = await(client.secrets().kvV2ReadAsync(path, SECRET.toBuilder().responseWrappingTtl(Duration.ofMinutes(1)).build()));
            var unwrapped = await(client.unwrapAsync(wrapped.wrapInfo().token(), KvV2ReadResponse::fromJson));
            await(client.secrets().kvV2DeleteMetadataAndAllVersionsAsync(path, SECRET));

            assertNull(wrapped.data());
            assertEquals("wrapped", unwrapped.data().getData().get("k").asString());
        }
    }

    @Test
    void aTokenCreated_IsProtected_AndWorks() {
        try (var client = create()) {
            var created = await(client.auth().tokenCreateAsync(new TokenCreateRequest().setPolicies(List.of("default")).setTtl("5m")));
            var child = client.copy();
            child.setToken(created.auth().clientToken());
            var self = await(child.auth().tokenLookUpSelfAsync());
            await(child.auth().tokenRevokeSelfAsync());

            assertTrue(self.data().get("policies").readList(JsonValue::readString).contains("default"));
        }
    }
}
