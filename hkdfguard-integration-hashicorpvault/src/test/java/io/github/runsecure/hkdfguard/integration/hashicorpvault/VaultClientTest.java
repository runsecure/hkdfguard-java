package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import static io.github.runsecure.hkdfguard.integration.hashicorpvault.Futures.assertFailsWith;
import static io.github.runsecure.hkdfguard.integration.hashicorpvault.Futures.await;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.integration.hashicorpvault.schema.AppRoleLoginRequest;
import io.github.runsecure.hkdfguard.integration.hashicorpvault.schema.KvV2ReadResponse;
import java.io.ByteArrayInputStream;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class VaultClientTest {
    @ParameterizedTest
    @CsvSource({"/v1/path/to/a,/v1/path/to/a", "v1/path/to/a,/v1/path/to/a", "/path/to/a,/v1/path/to/a", "path/to/a,/v1/path/to/a"})
    void v1Path_PrefixesPathsWithV1(String path, String expected) {
        assertEquals(expected, VaultClient.v1Path(path));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "a", "/", "v1", "//x/v1/"})
    void v1Path_AlwaysStartsWithV1_AndEndsWithThePath(String path) {
        var v1 = VaultClient.v1Path(path);
        assertTrue(v1.startsWith("/v1/"));
        assertTrue(v1.endsWith(path));
    }

    @Test
    void readAsync_GetsThePath_WithTheTokenAndClientHeaders() {
        try (var t = TestClient.create()) {
            t.vault().then(200, "{\"request_id\":\"r1\",\"data\":{\"key1\":\"value1\",\"n\":12}}");

            var response = await(t.client().readAsync("secret/foo"));

            var request = t.vault().single();
            assertEquals("GET", request.method());
            assertEquals("/v1/secret/foo", request.pathAndQuery());
            assertEquals(FakeVault.TOKEN, request.header("X-Vault-Token"));
            assertEquals("true", request.header("X-Vault-Request"));
            assertTrue(request.header("User-Agent").startsWith("hkdfguard-integration-hashicorpvault/"));
            assertNull(request.bodyText());

            assertEquals("r1", response.requestId());
            assertEquals("value1", response.data().get("key1").asString());
            assertEquals(12, response.data().get("n").asLong());
        }
    }

    @Test
    void callbacksNeverSeeTheToken() {
        var seenByRequestCallback = new AtomicReference<>("unset");
        var seenByResponseCallback = new AtomicReference<>("unset");
        try (var t = TestClient.create()) {
            t.client().setRequestCallbacks(b -> seenByRequestCallback.set(b.copy().build().headers().firstValue("X-Vault-Token").orElse(null)));
            t.client().setResponseCallbacks((r, s, h) -> seenByResponseCallback.set(r.headers().firstValue("X-Vault-Token").orElse(null)));

            await(t.client().readAsync("secret/foo"));

            assertEquals(FakeVault.TOKEN, t.vault().single().header("X-Vault-Token"));
            assertNull(seenByRequestCallback.get());
            assertNull(seenByResponseCallback.get());
        }
    }

    @Test
    void withoutAToken_NoTokenHeaderIsSent() {
        try (var t = TestClient.create(null, false, null)) {
            await(t.client().readAsync("a"));
            assertNull(t.vault().single().header("X-Vault-Token"));
        }
    }

    @Test
    void setToken_ProtectsIt_AndARequestsOwnTokenWins() {
        try (var t = TestClient.create(null, false, null)) {
            t.client().setToken("hvs.client");
            await(t.client().readAsync("a"));
            await(t.client().readAsync("b", VaultRequestOptions.builder().token(t.client().protectToken("hvs.request")).build()));
            t.client().clearToken();
            await(t.client().readAsync("c"));

            var requests = t.vault().requests();
            assertEquals("hvs.client", requests.get(0).header("X-Vault-Token"));
            assertEquals("hvs.request", requests.get(1).header("X-Vault-Token"));
            assertNull(requests.get(2).header("X-Vault-Token"));
        }
    }

    @Test
    void anUnprotectedToken_FailsTheRequest_WithoutQuotingIt() {
        try (var t = TestClient.create(null, false, null)) {
            t.client().setToken(new StaticVaultToken("hvs.plain-token-not-protected"));

            var e = assertFailsWith(IllegalStateException.class, t.client().readAsync("a"));

            assertFalse(e.getMessage().contains("plain-token"));
            assertNull(e.getCause());
            assertTrue(t.vault().requests().isEmpty());
        }
    }

    @Test
    void aProviderReturningNoToken_FailsTheRequest() {
        try (var t = TestClient.create(null, false, null)) {
            t.client().setToken(() -> CompletableFuture.completedFuture(""));
            assertFailsWith(IllegalStateException.class, t.client().readAsync("a"));
            t.client().setToken(() -> null);
            assertFailsWith(IllegalStateException.class, t.client().readAsync("a"));
            t.client().setToken(() -> CompletableFuture.failedFuture(new ArithmeticException("provider")));
            assertEquals("provider", assertFailsWith(ArithmeticException.class, t.client().readAsync("a")).getMessage());
            assertTrue(t.vault().requests().isEmpty());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "has space", "tab\t", "non-ascii-\u00e9"})
    void protectToken_RefusesWhatCantGoInAHeader(String token) {
        try (var t = TestClient.create()) {
            assertThrows(IllegalArgumentException.class, () -> t.client().protectToken(token));
            assertThrows(IllegalArgumentException.class, () -> t.client().setToken(token));
        }
    }

    @Test
    void aTokenProtectedForSomethingElse_FailsTheRequest() {
        try (var t = TestClient.create(null, false, null)) {
            var other = TestRings.ring().createProtector("something else");
            t.client().setToken(StaticVaultToken.protect(other, FakeVault.TOKEN));

            assertFailsWith(IllegalStateException.class, t.client().readAsync("a"));
            assertTrue(t.vault().requests().isEmpty());
        }
    }

    @Test
    void anAddressPath_IsKeptAsAPrefix() {
        try (var vault = new FakeVault()) {
            try (var t = TestClient.create(o -> o.address(java.net.URI.create(vault.address() + "/proxy/vault/")))) {
                await(t.client().readAsync("secret/foo"));
                assertEquals("/proxy/vault/v1/secret/foo", vault.single().pathAndQuery());
            }
        }
    }

    @Test
    void namespace_FromOptions_IsOverriddenPerRequest_AndCleared() {
        try (var t = TestClient.create(o -> o.namespace("ns1"))) {
            await(t.client().readAsync("a"));
            await(t.client().readAsync("b", VaultRequestOptions.builder().namespace("ns2").build()));
            await(t.client().readAsync("c", VaultRequestOptions.builder().namespace("").build()));
            t.client().setNamespace("ns3");
            await(t.client().readAsync("d"));
            t.client().clearNamespace();
            await(t.client().readAsync("e"));
            t.client().setNamespace("ns4");
            t.client().setNamespace("");
            await(t.client().readAsync("f"));

            assertEquals(Arrays.asList("ns1", "ns2", "ns1", "ns3", null, null),
                    t.vault().requests().stream().map(r -> r.header("X-Vault-Namespace")).toList());
            assertThrows(IllegalArgumentException.class, () -> t.client().setNamespace("bad\u0001"));
            assertThrows(IllegalArgumentException.class,
                    () -> t.client().readAsync("a", VaultRequestOptions.builder().namespace("bad\n").build()));
        }
    }

    @Test
    void mfaCredentials_AreAppended_ClientsFirst() {
        try (var t = TestClient.create()) {
            t.client().setMfaCredentials("a:1");
            await(t.client().readAsync("a", VaultRequestOptions.builder().mfaCredentials("b:2").build()));
            t.client().clearMfaCredentials();
            await(t.client().readAsync("b"));

            assertEquals(List.of("a:1", "b:2"), t.vault().requests().get(0).headers().get("X-Vault-MFA"));
            assertNull(t.vault().requests().get(1).header("X-Vault-MFA"));
            assertThrows(IllegalArgumentException.class, () -> t.client().setMfaCredentials(""));
            assertThrows(IllegalArgumentException.class, () -> t.client().setMfaCredentials("bad\u0001"));
        }
    }

    @Test
    void responseWrapping_SendsTheTtlAsAGoDuration_RequestsOverridingTheClient() {
        try (var t = TestClient.create()) {
            t.client().setResponseWrapping(Duration.ofMinutes(5));
            await(t.client().readAsync("a"));
            await(t.client().readAsync("b", VaultRequestOptions.builder().responseWrappingTtl(Duration.ofSeconds(90)).build()));
            await(t.client().readAsync("c", VaultRequestOptions.builder().responseWrappingTtl(Duration.ZERO).build()));
            t.client().clearResponseWrapping();
            await(t.client().readAsync("d"));

            assertEquals(Arrays.asList("5m0s", "1m30s", "5m0s", null),
                    t.vault().requests().stream().map(r -> r.header("X-Vault-Wrap-TTL")).toList());
            assertThrows(IllegalArgumentException.class, () -> t.client().setResponseWrapping(Duration.ofSeconds(-1)));
        }
    }

    @Test
    void replicationForwardingMode_SendsItsHeader() {
        try (var t = TestClient.create()) {
            t.client().setReplicationForwardingMode(ReplicationForwardingMode.ALWAYS);
            await(t.client().readAsync("a"));
            await(t.client().readAsync("b", VaultRequestOptions.builder().replicationForwardingMode(ReplicationForwardingMode.INCONSISTENT).build()));
            t.client().clearReplicationForwardingMode();
            await(t.client().readAsync("c"));

            var requests = t.vault().requests();
            assertEquals("active-node", requests.get(0).header("X-Vault-Forward"));
            assertNull(requests.get(0).header("X-Vault-Inconsistent"));
            assertEquals("forward-active-node", requests.get(1).header("X-Vault-Inconsistent"));
            assertNull(requests.get(1).header("X-Vault-Forward"));
            assertNull(requests.get(2).header("X-Vault-Forward"));
            assertNull(requests.get(2).header("X-Vault-Inconsistent"));
        }
    }

    @Test
    void customHeaders_RequestsReplaceSameNamedOnes_AndKeepTheRest() {
        try (var t = TestClient.create()) {
            t.client().setCustomHeaders(Map.of("X-One", List.of("1"), "X-Two", List.of("2a", "2b")));
            await(t.client().readAsync("a", VaultRequestOptions.builder().customHeaders(Map.of("x-two", List.of("replaced"))).build()));
            await(t.client().readAsync("b"));
            t.client().clearCustomHeaders();
            await(t.client().readAsync("c"));

            var requests = t.vault().requests();
            assertEquals("1", requests.get(0).header("X-One"));
            assertEquals("replaced", requests.get(0).header("X-Two"));
            assertEquals("2a,2b", requests.get(1).header("X-Two"));
            assertNull(requests.get(2).header("X-One"));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"x-vault-something", "X-Vault-Something", " ", "Host", "Content-Length"})
    void customHeaders_RefuseTheClientsOwnPrefix_AndWhatCantBeSent(String name) {
        try (var t = TestClient.create()) {
            assertThrows(IllegalArgumentException.class, () -> t.client().setCustomHeaders(Map.of(name, List.of("v"))));
            assertThrows(IllegalArgumentException.class,
                    () -> t.client().readAsync("a", VaultRequestOptions.builder().customHeaders(Map.of(name, List.of("v"))).build()));
            assertTrue(t.vault().requests().isEmpty());
        }
    }

    @Test
    void aCustomContentType_ReplacesTheClients() {
        try (var t = TestClient.create()) {
            await(t.client().writeAsync("a", Map.of("k", "v"), VaultRequestOptions.builder().customHeaders(Map.of("Content-Type", List.of("text/plain"))).build()));
            await(t.client().writeAsync("b", Map.of("k", "v")));

            assertEquals("text/plain", t.vault().requests().get(0).header("Content-Type"));
            assertEquals("application/json", t.vault().requests().get(1).header("Content-Type"));
        }
    }

    @Test
    void aLongToken_IsSent_AndALongLoginTokenProtected() {
        var longToken = "hvs." + "x".repeat(3000);
        try (var t = TestClient.create(null, false, null)) {
            t.client().setToken(longToken);
            t.vault().then(200, "{\"auth\":{\"client_token\":\"" + longToken + "\"}}");

            var response = await(t.client().readAsync("a"));

            assertEquals(longToken.length(), t.vault().single().header("X-Vault-Token").length());
            assertTrue(longToken.equals(t.vault().single().header("X-Vault-Token")));
            assertTrue(longToken.equals(t.decrypt(response.auth().clientToken())));
        }
    }

    @Test
    void aProtectedValueThatIsntAToken_FailsTheRequest() {
        try (var t = TestClient.create(null, false, null)) {
            t.client().setToken(new StaticVaultToken(t.protector().encrypt("has space")));
            assertFailsWith(IllegalStateException.class, t.client().readAsync("a"));
            assertTrue(t.vault().requests().isEmpty());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"[1]", "{\"a\":", "not json", "{\"data\":1} x"})
    void aResponseThatIsntAJsonObject_FailsWithVaultJsonException(String body) {
        try (var t = TestClient.create()) {
            t.vault().then(200, body);
            assertFailsWith(VaultJsonException.class, t.client().readAsync("a"));
        }
    }

    @Test
    void queryParameters_AreSortedByName_AndEscaped_AndListAddsListTrue() {
        try (var t = TestClient.create()) {
            await(t.client().readAsync("a", VaultRequestOptions.builder()
                    .queryParameter("z", "last").queryParameter("a b", "x&y=z/\u00e9").queryParameter("m", "1").queryParameter("m", "2").build()));
            await(t.client().listAsync("dir", VaultRequestOptions.builder().queryParameter("after", "k").build()));
            await(t.client().deleteAsync("gone", VaultRequestOptions.builder().queryParameter("q", "1").build()));

            var requests = t.vault().requests();
            assertEquals("/v1/a?a%20b=x%26y%3Dz%2F%C3%A9&m=1&m=2&z=last", requests.get(0).pathAndQuery());
            assertEquals("/v1/dir?after=k&list=true", requests.get(1).pathAndQuery());
            assertEquals("DELETE", requests.get(2).method());
            assertEquals("/v1/gone?q=1", requests.get(2).pathAndQuery());
        }
    }

    @Test
    void writeAsync_PostsTheBodyAsJson() {
        try (var t = TestClient.create()) {
            var body = new LinkedHashMap<String, Object>();
            body.put("s", "v\"\n");
            body.put("n", 7);
            body.put("b", true);
            body.put("nested", Map.of("list", List.of(1, "two")));
            body.put("none", null);

            await(t.client().writeAsync("secret/data/foo", body));

            var request = t.vault().single();
            assertEquals("POST", request.method());
            assertEquals("/v1/secret/data/foo", request.pathAndQuery());
            assertEquals("application/json", request.header("Content-Type"));
            assertEquals("{\"s\":\"v\\\"\\n\",\"n\":7,\"b\":true,\"nested\":{\"list\":[1,\"two\"]},\"none\":null}", request.bodyText());
        }
    }

    @Test
    void writeFromBytesAndStream_PostTheBodyAsItIs() {
        try (var t = TestClient.create()) {
            var bytes = "{\"raw\":1}".getBytes(StandardCharsets.UTF_8);
            await(t.client().writeFromBytesAsync("a", bytes));
            await(t.client().writeFromStreamAsync("b", new ByteArrayInputStream("{\"stream\":2}".getBytes(StandardCharsets.UTF_8))));

            assertEquals("{\"raw\":1}", t.vault().requests().get(0).bodyText());
            assertEquals("{\"stream\":2}", t.vault().requests().get(1).bodyText());
            assertArrayEquals("{\"raw\":1}".getBytes(StandardCharsets.UTF_8), bytes);
        }
    }

    @Test
    void anUnwritableBody_ThrowsFromTheCall() {
        try (var t = TestClient.create()) {
            assertThrows(IllegalArgumentException.class, () -> t.client().writeAsync("a", Map.of("x", new Object())));
            assertThrows(IllegalArgumentException.class, () -> t.client().writeAsync("a", Map.of("x", Double.NaN)));
            assertThrows(NullPointerException.class, () -> t.client().writeAsync(null, Map.of()));
            assertThrows(NullPointerException.class, () -> t.client().readAsync(null));
            assertTrue(t.vault().requests().isEmpty());
        }
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "''|false|-1",
        "{}|true|0",
        "{\"data\":{\"key1\":\"value1\",\"key2\":\"value2\"}}|true|2",
        "{\"key1\":\"value1\",\"key2\":\"value2\"}|true|2"})
    void responses_AreTheEnvelope_OrWholeAsData_OrNullWhenEmpty(String body, boolean expectResponse, int expectedKeys) {
        try (var t = TestClient.create()) {
            t.vault().then(200, body);

            var response = await(t.client().readAsync("a"));

            assertEquals(expectResponse, response != null);
            if (expectResponse)
                assertEquals(expectedKeys, response.data().size());
        }
    }

    @Test
    void theEnvelope_IsReadWhole() {
        try (var t = TestClient.create()) {
            t.vault().then(200, """
                    {"request_id":"r","lease_id":"l","lease_duration":3600,"renewable":true,"data":null,"warnings":["w1"],"mount_type":"kv",
                     "auth":{"client_token":"hvs.login-token","accessor":"acc","policies":["default"],"token_policies":["default"],
                             "identity_policies":[],"metadata":{"role":"r1"},"orphan":true,"entity_id":"e","lease_duration":60,"renewable":true,
                             "mfa_requirement":{"mfa_request_id":"m","mfa_constraints":{"c":{"any":[{"type":"totp","id":"i","uses_passcode":true}]}}}},
                     "wrap_info":null}
                    """);

            var response = await(t.client().readAsync("a"));

            assertEquals("r", response.requestId());
            assertEquals("l", response.leaseId());
            assertEquals(3600, response.leaseDuration());
            assertTrue(response.renewable());
            assertNull(response.data());
            assertEquals(List.of("w1"), response.warnings());
            assertNull(response.wrapInfo());
            var auth = response.auth();
            assertEquals("hvs.login-token", t.decrypt(auth.clientToken()));
            assertEquals("acc", auth.accessor());
            assertEquals(List.of("default"), auth.policies());
            assertEquals(List.of("default"), auth.tokenPolicies());
            assertEquals(List.of(), auth.identityPolicies());
            assertEquals(Map.of("role", "r1"), auth.metadata());
            assertTrue(auth.orphan());
            assertEquals("e", auth.entityId());
            assertEquals(60, auth.leaseDuration());
            assertTrue(auth.renewable());
            var method = auth.mfaRequirement().mfaConstraints().get("c").any().getFirst();
            assertEquals("m", auth.mfaRequirement().mfaRequestId());
            assertEquals(new VaultMfaRequirement.MethodId("totp", "i", true), method);
        }
    }

    @Test
    void aLoginsToken_IsProtectedAsItIsRead_AndCanBeSetAsTheClientsToken() {
        try (var t = TestClient.create(null, false, null)) {
            t.vault().then(200, "{\"auth\":{\"client_token\":\"hvs.issued-by-login\",\"accessor\":\"a\"},\"data\":{\"echo\":\"x\"}}");

            var login = await(t.client().auth().appRoleLoginAsync(new AppRoleLoginRequest().setRoleId("role").setSecretId("secret")));
            var token = login.auth().clientToken();
            t.client().setToken(token);
            await(t.client().readAsync("secret/foo"));

            assertFalse(token.toString().contains("issued-by-login"));
            assertEquals("hvs.issued-by-login", t.decrypt(token));
            assertFalse(login.toString().contains("issued-by-login"));
            var requests = t.vault().requests();
            assertEquals("/v1/auth/approle/login", requests.get(0).pathAndQuery());
            assertEquals("{\"role_id\":\"role\",\"secret_id\":\"secret\"}", requests.get(0).bodyText());
            assertEquals("hvs.issued-by-login", requests.get(1).header("X-Vault-Token"));
        }
    }

    @Test
    void aLoginsTokenEscapedInJson_IsUnescapedBeforeItsProtected() {
        try (var t = TestClient.create()) {
            t.vault().then(200, "{\"auth\":{\"client_token\":\"hvs.a\\u0062c\\/d\"}}");
            assertEquals("hvs.abc/d", t.decrypt(await(t.client().readAsync("a")).auth().clientToken()));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"auth\":{\"client_token\":\"\"}}", "{\"auth\":{\"client_token\":null}}", "{\"auth\":{}}"})
    void noLoginToken_IsNull(String body) {
        try (var t = TestClient.create()) {
            t.vault().then(200, body);
            assertNull(await(t.client().readAsync("a")).auth().clientToken());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"auth\":{\"client_token\":\"has space\"}}", "{\"auth\":{\"client_token\":12}}",
        "{\"auth\":{\"client_token\":\"hvs.\u00e9\"}}", "{\"auth\":[]}", "{\"wrap_info\":{\"token\":\"bad token\"}}"})
    void aLoginTokenThatIsntOne_FailsTheResponse(String body) {
        try (var t = TestClient.create()) {
            t.vault().then(200, body);
            var e = assertFailsWith(VaultJsonException.class, t.client().readAsync("a"));
            assertFalse(e.getMessage().contains("has space"));
        }
    }

    @Test
    void unwrapAsync_PutsWithTheWrappingToken_AndReadsTheWrappedResponse() {
        try (var t = TestClient.create()) {
            t.vault().then(200, """
                    {"wrap_info":{"token":"hvs.wrapping","accessor":"wa","ttl":300,"creation_time":"2024-05-06T07:08:09.123456789Z",
                                  "creation_path":"secret/data/foo","wrapped_accessor":""}}
                    """);
            t.vault().then(200, "{\"data\":{\"data\":{\"k\":\"unwrapped\"},\"metadata\":{\"version\":1}}}");

            var wrapped = await(t.client().readAsync("secret/data/foo", VaultRequestOptions.builder().responseWrappingTtl(Duration.ofMinutes(5)).build()));
            var info = wrapped.wrapInfo();
            var unwrapped = await(t.client().unwrapAsync(info.token(), KvV2ReadResponse::fromJson));

            assertEquals("wa", info.accessor());
            assertEquals(300, info.ttl());
            assertEquals("secret/data/foo", info.creationPath());
            assertEquals(OffsetDateTime.of(2024, 5, 6, 7, 8, 9, 123456789, ZoneOffset.UTC), info.creationTime());
            assertEquals("hvs.wrapping", t.decrypt(info.token()));
            assertEquals("unwrapped", unwrapped.data().getData().get("k").asString());
            var unwrap = t.vault().requests().getLast();
            assertEquals("PUT", unwrap.method());
            assertEquals("/v1/sys/wrapping/unwrap", unwrap.pathAndQuery());
            assertEquals("hvs.wrapping", unwrap.header("X-Vault-Token"));
            assertEquals("5m0s", t.vault().requests().getFirst().header("X-Vault-Wrap-TTL"));
        }
    }

    @Test
    void unwrapAsync_WithoutAReader_ReadsJsonValues() {
        try (var t = TestClient.create()) {
            t.vault().then(200, "{\"data\":{\"k\":\"v\"}}");
            assertEquals("v", await(t.client().unwrapAsync(t.client().protectToken("hvs.w"))).data().get("k").asString());
        }
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "500|{\"errors\":[\"error1\", \"error2\"]}|error1;error2||500 Internal Server Error: error1, error2",
        "410|{\"error\":\"single error\"}|single error||410: single error",
        "404|{\"data\":{\"key1\":\"value1\"}}|||404 Not Found: {\"data\":{\"key1\":\"value1\"}}",
        "404|{\"errors\":[]}|||404 Not Found: {\"errors\":[]}",
        "400|{\"errors\":[1, \"x\"]}|||400 Bad Request: {\"errors\":[1, \"x\"]}",
        "418|this is just a string|||418: this is just a string",
        "403|''|||403 Forbidden",
        "400|{\"error\":5}|||400 Bad Request: {\"error\":5}",
        "400|{\"errors\":\"one\"}|||400 Bad Request: {\"errors\":\"one\"}",
        "400|{\"other\":[1],\"error\":\"\"}|||400 Bad Request: {\"other\":[1],\"error\":\"\"}",
        "400|[\"x\"]|||400 Bad Request: [\"x\"]"})
    void vaultsRefusals_FailWithItsErrors_OrItsBody(int status, String body, String errors, String unused, String message) {
        try (var t = TestClient.create(o -> o.retry(VaultRetryOptions.builder().retryMax(0).build()))) {
            t.vault().then(status, body);

            var e = assertFailsWith(VaultResponseException.class, t.client().readAsync("a"));

            assertEquals(status, e.statusCode());
            assertEquals(message, e.getMessage());
            assertEquals(errors == null ? List.of() : List.of(errors.split(";")), e.errors());
            if (errors == null && !body.isEmpty())
                assertEquals(body, new String(e.rawResponseBytes(), StandardCharsets.UTF_8));
            else
                assertNull(e.rawResponseBytes());
            assertEquals("GET", e.requestMethod());
            assertEquals("/v1/a", e.requestUri().getPath());
            assertNull(e.requestUri().getQuery());
            assertTrue(VaultClient.isErrorStatus(new CompletionException(e), status));
            assertFalse(VaultClient.isErrorStatus(e, status + 1));
        }
    }

    @Test
    void isErrorStatus_IsFalseForOtherExceptions() {
        assertFalse(VaultClient.isErrorStatus(new IllegalStateException(), 404));
        assertFalse(VaultClient.isErrorStatus(null, 404));
        assertFalse(VaultClient.isErrorStatus(new VaultRequestException("plain", 404), 404));
    }

    @ParameterizedTest
    @ValueSource(ints = {429, 472, 503, 501})
    void sysHealth_IsNeverAnError_ItsStatusIsTheHealth(int status) {
        try (var t = TestClient.create(o -> o.retry(VaultRetryOptions.builder().retryMax(0).build()))) {
            t.vault().then(status, "{\"initialized\":true,\"sealed\":true}");

            var health = await(t.client().system().readHealthStatusAsync());

            assertTrue(health.data().get("sealed").asBoolean());
            assertEquals("/v1/sys/health", t.vault().single().pathAndQuery());
        }
    }

    @Test
    void a304_IsNotAnError() {
        try (var t = TestClient.create()) {
            t.vault().then(304, "");
            assertNull(await(t.client().readAsync("a")));
        }
    }

    @Test
    void readRawAsync_ReturnsTheResponseUnchecked() throws Exception {
        try (var t = TestClient.create(o -> o.requestTimeout(Duration.ofMillis(1)))) {
            t.vault().delayMillis = 50;
            t.vault().then(404, "raw body", "X-Extra", "1");

            try (var raw = await(t.client().readRawAsync("a", VaultRequestOptions.builder().queryParameter("q", "1").build()))) {
                assertEquals(404, raw.statusCode());
                assertEquals("1", raw.headers().firstValue("X-Extra").orElseThrow());
                assertEquals("raw body", new String(raw.body().readAllBytes(), StandardCharsets.UTF_8));
            }
            assertEquals("/v1/a?q=1", t.vault().single().pathAndQuery());
            assertEquals(FakeVault.TOKEN, t.vault().single().header("X-Vault-Token"));
        }
    }

    @Test
    void callbacks_ClientsRunBeforeRequests() {
        var calls = Collections.synchronizedList(new ArrayList<String>());
        try (var t = TestClient.create()) {
            t.client().setRequestCallbacks(b -> calls.add("client request"));
            t.client().setResponseCallbacks((r, s, h) -> calls.add("client response " + s));

            await(t.client().readAsync("a", VaultRequestOptions.builder()
                    .requestCallbacks(b -> b.header("x-added", "yes"))
                    .responseCallbacks((r, s, h) -> calls.add("request response " + r.uri().getPath()))
                    .build()));
            t.client().clearRequestCallbacks();
            t.client().clearResponseCallbacks();
            await(t.client().readAsync("b"));

            assertEquals(List.of("client request", "client response 200", "request response /v1/a"), calls);
            assertEquals("yes", t.vault().requests().getFirst().header("x-added"));
        }
    }

    @Test
    void aThrowingResponseCallback_FailsTheRequest() {
        try (var t = TestClient.create()) {
            assertFailsWith(ArithmeticException.class, t.client().readAsync("a", VaultRequestOptions.builder()
                    .responseCallbacks((r, s, h) -> {
                        throw new ArithmeticException();
                    }).build()));
        }
    }

    @Test
    void copy_CopiesSettings_WhichThenChangeIndependently_AndSharesConnections() {
        try (var t = TestClient.create(o -> o.requestTimeout(Duration.ofSeconds(30)))) {
            t.client().setNamespace("test-namespace");
            var copy = t.client().copy();
            copy.setNamespace("copy-namespace");

            await(t.client().readAsync("a"));
            await(copy.readAsync("b"));
            copy.close();
            await(t.client().readAsync("c"));

            assertEquals(List.of("test-namespace", "copy-namespace", "test-namespace"),
                    t.vault().requests().stream().map(r -> r.header("X-Vault-Namespace")).toList());
            assertEquals(FakeVault.TOKEN, t.vault().requests().get(1).header("X-Vault-Token"));
            assertSame(t.client().options(), copy.options());
            assertEquals(Duration.ofSeconds(30), copy.options().requestTimeout());

            t.client().close();
            assertFailsWith(IllegalStateException.class, copy.readAsync("d"));
            assertFailsWith(IllegalStateException.class, t.client().readAsync("d"));
        }
    }

    @Test
    void cancellingTheFuture_AbandonsTheRequest() {
        try (var t = TestClient.create()) {
            t.vault().delayMillis = 5_000;
            var future = t.client().readAsync("a");
            Futures.sleep(200);

            assertTrue(future.cancel(true));
            assertTrue(future.isCancelled());
        }
    }

    @Test
    void userAgent_NamesTheLibraryAndPlatform_InPrintableAscii() {
        var agent = VaultUserAgent.create("1.2.3", "Some\tOS\u00e9 10", "amd64", "25");

        assertEquals("hkdfguard-integration-hashicorpvault/1.2.3 (Some OS  10; amd64; Java 25)", agent);
        assertTrue(VaultUserAgent.create(null, "os", "arch", "21").startsWith("hkdfguard-integration-hashicorpvault/0.0.0 "));
        assertNotNull(VaultUserAgent.VALUE);
        assertTrue(VaultUserAgent.VALUE.chars().allMatch(c -> c >= ' ' && c <= '~'));
    }

    @Test
    void protectToken_HoldsOnlyTheProtectedForm() {
        try (var t = TestClient.create()) {
            var chars = "hvs.from-chars".toCharArray();
            var token = t.client().protectToken(CharBuffer.wrap(chars));

            assertFalse(token.toString().contains("from-chars"));
            assertEquals("hvs.from-chars", t.decrypt(token));
            assertEquals(token.toString(), await(token.getTokenAsync()));
        }
    }
}
