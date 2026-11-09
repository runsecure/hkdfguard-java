package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import static io.github.runsecure.hkdfguard.integration.hashicorpvault.Futures.await;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class VaultClientOptionsTest {
    private static VaultClient create(VaultClientOptions.Builder options) {
        return new VaultClient(TestRings.protector(), options.build());
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://vault.example.com:8200", "http://127.0.0.1:8200", "http://localhost:8200", "http://[::1]:8200",
        "https://vault.example.com/proxy/"})
    void anAddressThatKeepsTheTokenPrivate_IsAccepted(String address) {
        create(VaultClientOptions.builder().address(URI.create(address))).close();
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://vault.example.com:8200", "ftp://vault.example.com", "https://user:pass@vault.example.com",
        "https://vault.example.com/?q=1", "https://vault.example.com/#f", "unix:///var/run/vault.sock", "unix:///", "vault.example.com",
        "/relative", "mailto:vault@example.com"})
    void anAddressThatWouldExposeTheToken_OrCantBeReached_IsRefused(String address) {
        assertThrows(IllegalArgumentException.class, () -> create(VaultClientOptions.builder().address(URI.create(address))));
    }

    @Test
    void aUnixAddress_IsRefusedNamingWhy() {
        var e = assertThrows(IllegalArgumentException.class,
                () -> create(VaultClientOptions.builder().address(URI.create("unix:///var/run/vault.sock"))));
        assertTrue(e.getMessage().contains("unix socket"), e.getMessage());
    }

    @Test
    void httpAnywhere_IsAcceptedWhenAllowed() {
        create(VaultClientOptions.builder().address(URI.create("http://vault.example.com:8200")).allowUnencryptedHttp(true)).close();
    }

    @Test
    void aMissingAddressOrProtector_IsRefused() {
        assertThrows(NullPointerException.class, () -> VaultClientOptions.builder().address(null));
        assertThrows(NullPointerException.class, () -> new VaultClient(null));
    }

    @Test
    void negativeTimesAndUnsendableNamespaces_AreRefused() {
        assertThrows(IllegalArgumentException.class, () -> create(VaultClientOptions.builder().requestTimeout(Duration.ofSeconds(-1))));
        assertThrows(IllegalArgumentException.class,
                () -> create(VaultClientOptions.builder().retry(VaultRetryOptions.builder().retryWaitMin(Duration.ofMillis(-1)).build())));
        assertThrows(IllegalArgumentException.class,
                () -> create(VaultClientOptions.builder().retry(VaultRetryOptions.builder().retryWaitMax(Duration.ofMillis(-1)).build())));
        assertThrows(IllegalArgumentException.class, () -> create(VaultClientOptions.builder().namespace("bad\u0001")));
        create(VaultClientOptions.builder().namespace("")).close();
    }

    @Test
    void aSuppliedClientThatFollowsRedirects_IsRefused_AndOneThatDoesnt_IsUsedButNotClosed() {
        try (var redirecting = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build()) {
            assertThrows(IllegalArgumentException.class, () -> create(VaultClientOptions.builder().httpClient(redirecting)));
        }

        try (var vault = new FakeVault(); var supplied = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()) {
            var client = create(VaultClientOptions.builder().address(vault.address()).httpClient(supplied));
            await(client.readAsync("a"));
            client.close();

            assertFalse(supplied.isTerminated());
            assertEquals(1, vault.requests().size());
        }
    }

    @Test
    void tlsOptions_NeedTheClientsOwnHttpClient() {
        try (var supplied = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build()) {
            assertThrows(IllegalArgumentException.class, () -> create(VaultClientOptions.builder().httpClient(supplied)
                    .tls(VaultTlsOptions.builder().insecureSkipVerify(true).build())));
        }
    }

    @Test
    void noOptions_IsTheDefaults() {
        try (var client = new VaultClient(TestRings.protector())) {
            var options = client.options();
            assertEquals(URI.create("https://127.0.0.1:8200"), options.address());
            assertEquals(Duration.ofSeconds(60), options.requestTimeout());
            assertEquals(2, options.retry().retryMax());
            assertEquals(Duration.ofSeconds(1), options.retry().retryWaitMin());
            assertEquals(Duration.ofMillis(1500), options.retry().retryWaitMax());
            assertFalse(options.followRedirects());
            assertFalse(options.allowUnencryptedHttp());
            assertNull(options.token());
            assertNull(options.rateLimiter());
            assertTrue(options.tls().isEmpty());
        }
    }

    @Test
    void toBuilder_KeepsEveryOption() {
        var token = new StaticVaultToken("protected");
        var limiter = new VaultRateLimiter(1, 1);
        var original = VaultClientOptions.builder().address(URI.create("https://v:1")).allowUnencryptedHttp(true).requestTimeout(Duration.ofSeconds(3))
                .rateLimiter(limiter).enforceReadYourWritesConsistency(true).followRedirects(true).token(token).namespace("ns").build();

        var copy = original.toBuilder().build();

        assertEquals(URI.create("https://v:1"), copy.address());
        assertTrue(copy.allowUnencryptedHttp());
        assertEquals(Duration.ofSeconds(3), copy.requestTimeout());
        assertSame(limiter, copy.rateLimiter());
        assertTrue(copy.enforceReadYourWritesConsistency());
        assertTrue(copy.followRedirects());
        assertSame(token, copy.token());
        assertEquals("ns", copy.namespace());
        assertSame(original.tls(), copy.tls());
        assertSame(original.retry(), copy.retry());
    }

    @Test
    void tlsIsEmpty_OnlyWhenNothingIsSet() {
        assertTrue(VaultTlsOptions.builder().build().isEmpty());
        assertTrue(VaultTlsOptions.builder().serverCertificatePem(new byte[0]).build().isEmpty());
        assertFalse(VaultTlsOptions.builder().serverCertificateFile(Path.of("ca.pem")).build().isEmpty());
        assertFalse(VaultTlsOptions.builder().serverCertificatePem(new byte[] {1}).build().isEmpty());
        assertFalse(VaultTlsOptions.builder().serverCertificateDirectory(Path.of(".")).build().isEmpty());
        assertFalse(VaultTlsOptions.builder().clientCertificateFile(Path.of("c")).build().isEmpty());
        assertFalse(VaultTlsOptions.builder().clientCertificateKeyPem(new byte[] {1}).build().isEmpty());
        assertFalse(VaultTlsOptions.builder().serverName("vault").build().isEmpty());
        assertFalse(VaultTlsOptions.builder().insecureSkipVerify(true).build().isEmpty());
    }

    @Test
    void tlsOptions_CopyTheirArrays() {
        var pem = new byte[] {1, 2};
        var options = VaultTlsOptions.builder().serverCertificatePem(pem).build();
        pem[0] = 9;
        options.serverCertificatePem()[1] = 9;

        assertArrayEquals(new byte[] {1, 2}, options.serverCertificatePem());
        assertArrayEquals(new byte[] {1, 2}, options.toBuilder().build().serverCertificatePem());
    }

    @ParameterizedTest
    @CsvSource({"1,true", "t,true", "T,true", "TRUE,true", "true,true", "True,true",
        "0,false", "f,false", "F,false", "FALSE,false", "false,false", "False,false"})
    void fromEnvironment_ReadsBooleansAsGoDoes(String value, boolean expected) {
        var options = VaultClientOptions.fromEnvironment(Map.of("VAULT_SKIP_VERIFY", value)::get, null);
        assertEquals(expected, options.tls().insecureSkipVerify());
    }

    @Test
    void fromEnvironment_ReadsEveryVariable() {
        var tls = TlsMaterials.get();
        var protector = TestRings.protector();
        var variables = new HashMap<String, String>();
        variables.put("VAULT_ADDR", "https://ignored.example.com:8200");
        variables.put("VAULT_AGENT_ADDR", "https://agent.example.com:8100");
        variables.put("VAULT_CLIENT_TIMEOUT", "1m30s");
        variables.put("VAULT_RATE_LIMIT", "5:9");
        variables.put("VAULT_DISABLE_REDIRECTS", "true");
        variables.put("VAULT_TOKEN", "hvs.from-env");
        variables.put("VAULT_NAMESPACE", "team-a");
        variables.put("VAULT_SKIP_VERIFY", "false");
        variables.put("VAULT_CACERT", tls.directory.resolve("ca.pem").toString());
        variables.put("VAULT_CACERT_BYTES", tls.caPem);
        variables.put("VAULT_CAPATH", tls.directory.toString());
        variables.put("VAULT_CLIENT_CERT", "client.pem");
        variables.put("VAULT_CLIENT_KEY", "client.key");
        variables.put("VAULT_TLS_SERVER_NAME", "vault.test");
        variables.put("VAULT_RETRY_WAIT_MIN", "250ms");
        variables.put("VAULT_RETRY_WAIT_MAX", "2s");
        variables.put("VAULT_MAX_RETRIES", "7");

        var options = VaultClientOptions.fromEnvironment(variables::get, protector);

        assertEquals(URI.create("https://agent.example.com:8100"), options.address());
        assertEquals(Duration.ofSeconds(90), options.requestTimeout());
        assertEquals(5, options.rateLimiter().requestsPerSecond());
        assertEquals(9, options.rateLimiter().burst());
        assertFalse(options.followRedirects());
        assertEquals("hvs.from-env", TestRings.decrypt(protector, options.token().toString()));
        assertFalse(options.token().toString().contains("from-env"));
        assertEquals("team-a", options.namespace());
        var t = options.tls();
        assertFalse(t.insecureSkipVerify());
        assertEquals(tls.directory.resolve("ca.pem"), t.serverCertificateFile());
        assertArrayEquals(tls.caPem.getBytes(StandardCharsets.UTF_8), t.serverCertificatePem());
        assertEquals(tls.directory, t.serverCertificateDirectory());
        assertEquals(Path.of("client.pem"), t.clientCertificateFile());
        assertEquals(Path.of("client.key"), t.clientCertificateKeyFile());
        assertEquals("vault.test", t.serverName());
        assertEquals(Duration.ofMillis(250), options.retry().retryWaitMin());
        assertEquals(Duration.ofSeconds(2), options.retry().retryWaitMax());
        assertEquals(7, options.retry().retryMax());
    }

    @Test
    void fromEnvironment_WithNothingSet_IsTheDefaults() {
        var options = VaultClientOptions.fromEnvironment(Map.<String, String>of()::get, TestRings.protector());

        assertEquals(VaultClientOptions.DEFAULT_ADDRESS, options.address());
        assertEquals(Duration.ofSeconds(60), options.requestTimeout());
        assertNull(options.token());
        assertNull(options.namespace());
        assertNull(options.rateLimiter());
        assertTrue(options.tls().isEmpty());
    }

    @Test
    void fromEnvironment_ReadsTheProcessEnvironment() {
        var options = VaultClientOptions.fromEnvironment(null);
        var address = System.getenv("VAULT_AGENT_ADDR") != null && !System.getenv("VAULT_AGENT_ADDR").isEmpty() ? System.getenv("VAULT_AGENT_ADDR")
                : System.getenv("VAULT_ADDR") != null && !System.getenv("VAULT_ADDR").isEmpty() ? System.getenv("VAULT_ADDR") : null;
        assertEquals(address == null ? VaultClientOptions.DEFAULT_ADDRESS : URI.create(address), options.address());
        assertNull(options.token());
    }

    @ParameterizedTest
    @CsvSource({"10,10,10", "0.5,0.5,1", "3:7,3,7"})
    void fromEnvironment_ReadsARateWithOrWithoutABurst(String value, double rate, int burst) {
        var limiter = VaultClientOptions.fromEnvironment(Map.of("VAULT_RATE_LIMIT", value)::get, null).rateLimiter();
        assertEquals(rate, limiter.requestsPerSecond());
        assertEquals(burst, limiter.burst());
    }

    @Test
    void fromEnvironment_ProtectsVaultToken_OnlyGivenAProtector() {
        var variables = Map.of("VAULT_TOKEN", "hvs.env-token");

        assertNull(VaultClientOptions.fromEnvironment(variables::get, null).token());
        try (var vault = new FakeVault()) {
            var protector = TestRings.protector();
            var options = VaultClientOptions.fromEnvironment(variables::get, protector).toBuilder().address(vault.address()).build();
            try (var client = new VaultClient(protector, options)) {
                await(client.readAsync("a"));
            }
            assertEquals("hvs.env-token", vault.single().header("X-Vault-Token"));
        }
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "VAULT_ADDR|not a uri", "VAULT_ADDR|relative/path", "VAULT_CLIENT_TIMEOUT|60", "VAULT_RATE_LIMIT|fast", "VAULT_RATE_LIMIT|0",
        "VAULT_RATE_LIMIT|1:0", "VAULT_DISABLE_REDIRECTS|yes", "VAULT_SKIP_VERIFY|2", "VAULT_MAX_RETRIES|two",
        "VAULT_RETRY_WAIT_MIN|1x", "VAULT_RETRY_WAIT_MAX|-", "VAULT_TOKEN|has space"})
    void fromEnvironment_RefusesAValueThatIsntOne_NamingTheVariable(String name, String value) {
        var e = assertThrows(IllegalArgumentException.class, () -> VaultClientOptions.fromEnvironment(Map.of(name, value)::get, TestRings.protector()));
        assertTrue(e.getMessage().contains(name), e.getMessage());
        if (name.equals("VAULT_TOKEN"))
            assertFalse(e.getMessage().contains(value));
    }

    @Test
    void fromEnvironment_RefusesAnUnsendableNamespace() {
        var e = assertThrows(IllegalArgumentException.class, () -> VaultClientOptions.fromEnvironment(Map.of("VAULT_NAMESPACE", "bad\u0001")::get, null));
        assertTrue(e.getMessage().contains("VAULT_NAMESPACE"));
    }

    @Test
    void fromEnvironment_AnEmptyVariable_IsUnset() {
        var options = VaultClientOptions.fromEnvironment(Map.of("VAULT_ADDR", "", "VAULT_RETRY_WAIT_MAX", "")::get, null);
        assertEquals(VaultClientOptions.DEFAULT_ADDRESS, options.address());
    }

    @Test
    void fromEnvironment_DisableRedirectsFalse_LeavesThemAsTheyAre() {
        assertFalse(VaultClientOptions.fromEnvironment(Map.of("VAULT_DISABLE_REDIRECTS", "false")::get, null).followRedirects());
    }
}
