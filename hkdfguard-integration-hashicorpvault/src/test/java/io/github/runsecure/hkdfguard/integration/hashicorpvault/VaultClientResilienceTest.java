package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import static io.github.runsecure.hkdfguard.integration.hashicorpvault.Futures.assertFailsWith;
import static io.github.runsecure.hkdfguard.integration.hashicorpvault.Futures.await;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.event.Level;

class VaultClientResilienceTest {
    @ParameterizedTest
    @ValueSource(ints = {500, 502, 503, 429, 412})
    void aRetryableStatus_IsRetried_EachAttemptWithTheTokenAndBody(int status) {
        try (var t = TestClient.create()) {
            t.vault().then(status, "{\"errors\":[\"busy\"]}");

            await(t.client().writeAsync("a", Map.of("k", "v")));

            var requests = t.vault().requests();
            assertEquals(2, requests.size());
            for (var request : requests) {
                assertEquals(FakeVault.TOKEN, request.header("X-Vault-Token"));
                assertEquals("{\"k\":\"v\"}", request.bodyText());
            }
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {501, 400, 403, 404})
    void aStatusAnotherAttemptWouldGetToo_IsNotRetried(int status) {
        try (var t = TestClient.create()) {
            t.vault().then(status, "{\"errors\":[\"no\"]}");

            assertEquals(status, assertFailsWith(VaultResponseException.class, t.client().readAsync("a")).statusCode());
            assertEquals(1, t.vault().requests().size());
        }
    }

    @Test
    void onceRetriesRunOut_TheLastResponseIsTheError() {
        var count = new AtomicInteger();
        try (var t = TestClient.create()) {
            t.vault().respond = r -> new FakeVault.Answer(503, "{\"errors\":[\"attempt " + count.incrementAndGet() + "\"]}");

            var e = assertFailsWith(VaultResponseException.class, t.client().readAsync("a"));

            assertEquals(List.of("attempt 3"), e.errors());
            assertEquals(3, t.vault().requests().size());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1})
    void retryMaxOfZeroOrLess_RetriesNothing(int retryMax) {
        try (var t = TestClient.create(o -> o.retry(VaultRetryOptions.builder().retryMax(retryMax).build()))) {
            t.vault().respond = r -> new FakeVault.Answer(503, "");

            assertFailsWith(VaultResponseException.class, t.client().readAsync("a"));
            assertEquals(1, t.vault().requests().size());
        }
    }

    @Test
    void noAnswer_IsRetried_AndOnceRetriesRunOut_ItsExceptionPropagates() {
        try (var t = TestClient.create()) {
            t.vault().respond = r -> FakeVault.Answer.DROP;

            // A POST: java.net.http itself resends an idempotent GET once on a dropped connection.
            assertFailsWith(IOException.class, t.client().writeAsync("a", Map.of()));
            assertEquals(3, t.vault().requests().size());
        }
    }

    @Test
    void noAnswerThenAnAnswer_Succeeds() {
        try (var t = TestClient.create()) {
            t.vault().then(r -> FakeVault.Answer.DROP).then(200, "{\"data\":{\"k\":\"v\"}}");

            assertEquals("v", await(t.client().readAsync("a")).data().get("k").asString());
            assertEquals(2, t.vault().requests().size());
        }
    }

    @Test
    void theTokenProvider_IsAskedOncePerRequest_NotPerRetry() {
        var asked = new AtomicInteger();
        try (var t = TestClient.create(null, false, null)) {
            var token = t.client().protectToken(FakeVault.TOKEN);
            t.client().setToken(() -> {
                asked.incrementAndGet();
                return token.getTokenAsync();
            });
            t.vault().then(503, "").then(503, "");

            await(t.client().readAsync("a"));

            assertEquals(1, asked.get());
            assertEquals(3, t.vault().requests().size());
            assertTrue(t.vault().requests().stream().allMatch(r -> FakeVault.TOKEN.equals(r.header("X-Vault-Token"))));
        }
    }

    @Test
    void customRetryPolicyAndBackoff_AreUsed() {
        var seen = Collections.synchronizedList(new ArrayList<String>());
        try (var t = TestClient.create(o -> o.retry(VaultRetryOptions.builder()
                .retryMax(5)
                .retryWaitMin(Duration.ofMillis(3))
                .retryWaitMax(Duration.ofMillis(4))
                .checkRetry((status, failure) -> status == 418)
                .backoff((min, max, attempt, status) -> {
                    seen.add(min.toMillis() + "-" + max.toMillis() + " #" + attempt + " " + status);
                    return Duration.ZERO;
                })
                .build()))) {
            t.vault().then(418, "").then(418, "").then(500, "");

            assertEquals(500, assertFailsWith(VaultResponseException.class, t.client().readAsync("a")).statusCode());
            assertEquals(List.of("3-4 #0 418", "3-4 #1 418"), seen);
        }
    }

    @Test
    void retries_AreLogged_WithoutTheQuery() {
        var logger = new RecordingLogger();
        try (var t = TestClient.create(null, true, logger)) {
            t.vault().then(503, "");

            await(t.client().readAsync("auth/x/login", VaultRequestOptions.builder().queryParameter("secret_id", "hush").build()));

            var entry = logger.entries().getFirst();
            assertEquals(Level.WARN, entry.level());
            assertEquals(1, entry.eventId());
            assertTrue(entry.message().contains("GET /v1/auth/x/login"), entry.message());
            assertTrue(entry.message().contains("503 Service Unavailable"), entry.message());
            assertTrue(entry.message().contains("retry 1 of 2"), entry.message());
            assertFalse(entry.message().contains("hush"));
            assertFalse(entry.message().contains(FakeVault.TOKEN));
        }
    }

    @ParameterizedTest
    @CsvSource({"0,1000,1000,1000", "1,1000,1000,2000", "2,500,400,1500"})
    void linearJitterBackoff_IsTheMinTimesTheAttempts_WhenThereIsNoRange(int attempt, int min, int max, int expected) {
        assertEquals(Duration.ofMillis(expected), VaultRetryOptions.linearJitterBackoff(Duration.ofMillis(min), Duration.ofMillis(max), attempt, 0));
    }

    @Test
    void linearJitterBackoff_IsBetweenMinAndMax_TimesTheAttempts() {
        for (var i = 0; i < 100; i++) {
            var delay = VaultRetryOptions.linearJitterBackoff(Duration.ofMillis(100), Duration.ofMillis(200), 2, 500);
            assertTrue(delay.compareTo(Duration.ofMillis(300)) >= 0 && delay.compareTo(Duration.ofMillis(600)) < 0, delay.toString());
        }
    }

    @Test
    void defaultRetryPolicy_RetriesWhatAnotherAttemptMayNotMeet() {
        assertTrue(VaultRetryOptions.defaultRetryPolicy(0, null));
        assertTrue(VaultRetryOptions.defaultRetryPolicy(0, new IOException("reset")));
        assertFalse(VaultRetryOptions.defaultRetryPolicy(0, new SSLHandshakeException("refused")));
        assertFalse(VaultRetryOptions.defaultRetryPolicy(0, new IOException(new java.security.cert.CertificateException("refused"))));
        for (var status : new int[] {412, 429, 500, 502, 503, 504})
            assertTrue(VaultRetryOptions.defaultRetryPolicy(status, null), "" + status);
        for (var status : new int[] {200, 301, 400, 403, 404, 501})
            assertFalse(VaultRetryOptions.defaultRetryPolicy(status, null), "" + status);
    }

    @Test
    void aRedirect_FailsByDefault_NamingWhereItPointed() {
        try (var t = TestClient.create()) {
            t.vault().then(307, "", "Location", "/v1/elsewhere");

            var e = assertFailsWith(VaultRedirectException.class, t.client().readAsync("a"));

            assertEquals(307, e.statusCode());
            assertEquals("redirects are disabled", e.reason());
            assertEquals(t.vault().address().resolve("/v1/elsewhere"), e.redirectLocation());
            assertEquals("GET", e.requestMethod());
            assertEquals("/v1/a", e.requestUri().getPath());
            assertTrue(VaultClient.isErrorStatus(e, 307));
            assertEquals(1, t.vault().requests().size());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {301, 302, 307})
    void followRedirects_FollowsOne_WithTheSameMethodBodyAndToken(int status) {
        try (var t = TestClient.create(o -> o.followRedirects(true))) {
            t.vault().then(status, "", "Location", t.vault().address() + "/v1/b?x=1");

            await(t.client().writeAsync("a", Map.of("k", "v")));

            var requests = t.vault().requests();
            assertEquals(2, requests.size());
            assertEquals("/v1/b?x=1", requests.get(1).pathAndQuery());
            assertEquals("POST", requests.get(1).method());
            assertEquals("{\"k\":\"v\"}", requests.get(1).bodyText());
            assertEquals(FakeVault.TOKEN, requests.get(1).header("X-Vault-Token"));
        }
    }

    @Test
    void aRelativeRedirect_IsResolvedAgainstTheRequest() {
        try (var t = TestClient.create(o -> o.followRedirects(true))) {
            t.vault().then(307, "", "Location", "b");

            await(t.client().readAsync("dir/a"));

            assertEquals("/v1/dir/b", t.vault().requests().get(1).pathAndQuery());
        }
    }

    @Test
    void aSecondRedirect_Fails() {
        try (var t = TestClient.create(o -> o.followRedirects(true))) {
            t.vault().then(307, "", "Location", "/v1/b").then(307, "", "Location", "/v1/c");

            assertEquals("at most one redirect is allowed", assertFailsWith(VaultRedirectException.class, t.client().readAsync("a")).reason());
            assertEquals(2, t.vault().requests().size());
        }
    }

    @ParameterizedTest
    @CsvSource({"http://10.0.0.1:8200/v1/a,false", "ftp://vault.test/v1/a,true"})
    void aRedirectThatWouldExposeTheToken_Fails(String location, boolean allowHttp) {
        try (var t = TestClient.create(o -> o.followRedirects(true).allowUnencryptedHttp(allowHttp))) {
            t.vault().then(302, "", "Location", location);

            var e = assertFailsWith(VaultRedirectException.class, t.client().readAsync("a"));

            assertEquals("the redirect would send the token over unencrypted http", e.reason());
            assertEquals(URI.create(location), e.redirectLocation());
            assertEquals(1, t.vault().requests().size());
        }
    }

    @Test
    void anHttpRedirect_IsFollowedOnLoopback() {
        try (var t = TestClient.create(o -> o.followRedirects(true))) {
            t.vault().then(307, "", "Location", "http://localhost:" + t.vault().address().getPort() + "/v1/b");

            await(t.client().readAsync("a"));

            assertEquals("/v1/b", t.vault().requests().get(1).pathAndQuery());
        }
    }

    @Test
    void aRedirectWithoutALocation_Fails() {
        try (var t = TestClient.create(o -> o.followRedirects(true))) {
            t.vault().then(301, "");

            var e = assertFailsWith(VaultRedirectException.class, t.client().readAsync("a"));

            assertEquals("could not read the redirect location", e.reason());
            assertNull(e.redirectLocation());
        }
    }

    @Test
    void aRequestOutlivingTheTimeout_FailsWithTimeoutException() {
        try (var t = TestClient.create(o -> o.requestTimeout(Duration.ofMillis(300)))) {
            t.vault().delayMillis = 3_000;

            var started = System.nanoTime();
            var e = assertFailsWith(TimeoutException.class, t.client().readAsync("a"));

            assertTrue(e.getMessage().contains("GET /v1/a"), e.getMessage());
            assertTrue(Duration.ofNanos(System.nanoTime() - started).compareTo(Duration.ofSeconds(2)) < 0);
        }
    }

    @Test
    void aSlowTokenProvider_CountsAgainstTheTimeout() {
        try (var t = TestClient.create(o -> o.requestTimeout(Duration.ofMillis(200)))) {
            t.client().setToken(CompletableFuture::new);

            assertFailsWith(TimeoutException.class, t.client().readAsync("a"));
            assertTrue(t.vault().requests().isEmpty());
        }
    }

    @Test
    void aZeroTimeout_IsNone() {
        try (var t = TestClient.create(o -> o.requestTimeout(Duration.ZERO))) {
            t.vault().delayMillis = 100;
            await(t.client().readAsync("a"));
        }
    }

    @Test
    void theRateLimiter_SpacesRequestsOutOnceTheBurstIsSpent() {
        try (var t = TestClient.create(o -> o.rateLimiter(new VaultRateLimiter(10, 1)))) {
            var started = System.nanoTime();
            for (var i = 0; i < 3; i++)
                await(t.client().readAsync("a"));

            assertTrue(Duration.ofNanos(System.nanoTime() - started).compareTo(Duration.ofMillis(150)) >= 0);
            assertEquals(10, t.client().options().rateLimiter().requestsPerSecond());
            assertEquals(1, t.client().options().rateLimiter().burst());
        }
    }

    @Test
    void aRateLimitedRequestOutlivingTheTimeout_FailsAtOnce() {
        try (var t = TestClient.create(o -> o.rateLimiter(new VaultRateLimiter(0.1, 1)).requestTimeout(Duration.ofMillis(500)))) {
            await(t.client().readAsync("a"));
            assertFailsWith(TimeoutException.class, t.client().readAsync("b"));
            assertEquals(1, t.vault().requests().size());
        }
    }

    @Test
    void aRateLimitedWaitInterrupted_GivesItsTurnBack() throws Exception {
        var limiter = new VaultRateLimiter(2, 1);
        assertTrue(limiter.acquire(0));
        assertFalse(limiter.acquire(0));

        var interrupted = new AtomicBoolean();
        var waiter = Thread.ofVirtual().start(() -> {
            try {
                limiter.acquire(Long.MAX_VALUE);
            } catch (InterruptedException e) {
                interrupted.set(true);
            }
        });
        Futures.sleep(100);
        waiter.interrupt();
        waiter.join();
        assertTrue(interrupted.get());

        // Had the turn been kept, the next would wait a whole second; given back, at most half of one.
        var started = System.nanoTime();
        assertTrue(limiter.acquire(Duration.ofSeconds(5).toNanos()));
        assertTrue(Duration.ofNanos(System.nanoTime() - started).compareTo(Duration.ofMillis(700)) < 0);
    }

    @ParameterizedTest
    @CsvSource({"0,1", "-1,1", "NaN,1", "Infinity,1", "1,0"})
    void vaultRateLimiter_RefusesWhatIsntALimit(double rate, int burst) {
        assertThrows(IllegalArgumentException.class, () -> new VaultRateLimiter(rate, burst));
    }

    @Test
    void readYourWrites_SendsTheStatesSeen_AndACopysChangeIndependently() {
        var state1 = encode("v1:cid:1:0:");
        var state2 = encode("v1:cid:2:0:");
        try (var t = TestClient.create(o -> o.enforceReadYourWritesConsistency(true))) {
            t.vault().then(200, "{\"data\":{}}", "X-Vault-Index", state1);

            await(t.client().writeAsync("a", Map.of()));
            var copy = t.client().copy();
            t.vault().then(200, "{\"data\":{}}", "X-Vault-Index", state2);
            await(t.client().readAsync("b"));
            await(t.client().readAsync("c"));
            await(copy.readAsync("d"));

            var requests = t.vault().requests();
            assertNull(requests.get(0).header("X-Vault-Index"));
            assertEquals(state1, requests.get(1).header("X-Vault-Index"));
            assertEquals(state2, requests.get(2).header("X-Vault-Index"));
            assertEquals(state1, requests.get(3).header("X-Vault-Index"));
        }
    }

    @Test
    void withoutReadYourWrites_NoStatesAreSent() {
        try (var t = TestClient.create()) {
            t.vault().then(200, "{\"data\":{}}", "X-Vault-Index", encode("v1:cid:1:0:"));
            await(t.client().readAsync("a"));
            await(t.client().readAsync("b"));
            assertNull(t.vault().requests().get(1).header("X-Vault-Index"));
        }
    }

    private static String encode(String state) {
        return Base64.getEncoder().encodeToString(state.getBytes(StandardCharsets.UTF_8));
    }
}
