package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import static io.github.runsecure.hkdfguard.integration.hashicorpvault.Futures.await;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpTimeoutException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Flow;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class VaultHttpTest {
    @ParameterizedTest
    @CsvSource({
        "https://vault.example.com:8200,https://vault.example.com:8200/v1/",
        "https://vault.example.com:8200/,https://vault.example.com:8200/v1/",
        "https://vault.example.com/proxy/vault/,https://vault.example.com/proxy/vault/v1/",
        "HTTPS://vault.example.com,https://vault.example.com/v1/",
        "http://127.0.0.1:8200,http://127.0.0.1:8200/v1/",
        "http://localhost:8200,http://localhost:8200/v1/",
        "http://[::1]:8200,http://[::1]:8200/v1/"})
    void apiBase_IsV1UnderTheAddress_KeepingAPrefix(String address, String expected) {
        assertEquals(expected, VaultHttp.apiBase(URI.create(address), "a token"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://vault.example.com:8200", "http://10.0.0.1", "ftp://vault.example.com", "unix:///var/run/vault.sock",
        "https://user:pass@vault.example.com", "https://vault.example.com/?q=1", "https://vault.example.com/#f", "vault.example.com"})
    void apiBase_RefusesAnAddressThatWouldExposeTheToken(String address) {
        var e = assertThrows(IllegalArgumentException.class, () -> VaultHttp.apiBase(URI.create(address), "a token and DEKs"));
        assertTrue(e.getMessage().contains(address), e.getMessage());
    }

    @Test
    void apiBase_NamesWhatEveryRequestCarries_AndRefusesNull() {
        var e = assertThrows(IllegalArgumentException.class, () -> VaultHttp.apiBase(URI.create("http://vault.example.com"), "a token and DEKs"));
        assertTrue(e.getMessage().contains("a token and DEKs"));
        assertThrows(NullPointerException.class, () -> VaultHttp.apiBase(null, "a token"));
    }

    @Test
    void isLoopback_ParsesOnlyLiterals() {
        assertTrue(VaultHttp.isLoopback("localhost"));
        assertTrue(VaultHttp.isLoopback("LOCALHOST"));
        assertTrue(VaultHttp.isLoopback("127.0.0.1"));
        assertTrue(VaultHttp.isLoopback("127.1.2.3"));
        assertTrue(VaultHttp.isLoopback("[::1]"));
        assertFalse(VaultHttp.isLoopback("10.0.0.1"));
        assertFalse(VaultHttp.isLoopback("localhost.example.com"));
        assertFalse(VaultHttp.isLoopback(null));
    }

    @ParameterizedTest
    @CsvSource({"secret,true", "team-a/my_app/db.v2,true", "...x/x..,true", "'',false", "a//b,false", "/a,false", "a/,false", "a/./b,false",
        "a/../b,false", "a b,false", "a#b,false", "café,false"})
    void isValidPath_AcceptsOnlyPathsThatStayWhereTheyrePut(String path, boolean expected) {
        assertEquals(expected, VaultHttp.isValidPath(path));
    }

    @Test
    void isValidPath_RefusesNull() {
        assertFalse(VaultHttp.isValidPath(null));
        assertFalse(VaultHttp.isValidPathSegment(null));
    }

    @ParameterizedTest
    @CsvSource({"myapp-kek,true", "a/b,false", ".,false", "..,false", "'',false"})
    void isValidPathSegment_AcceptsOneSegment(String segment, boolean expected) {
        assertEquals(expected, VaultHttp.isValidPathSegment(segment));
        assertEquals(expected, VaultHttp.isValidSegment("x/" + segment + "/y", 2, 2 + segment.length()));
    }

    @ParameterizedTest
    @CsvSource({"hvs.CAESI,true", "!~,true", "'',false", "hvs.with space,false", "café,false"})
    void isValidToken_AcceptsWhatCanGoInAHeader(String token, boolean expected) {
        assertEquals(expected, VaultHttp.isValidToken(token));
        assertEquals(expected, VaultHttp.isValidToken(CharBuffer.wrap(token.toCharArray())));
    }

    @Test
    void isValidToken_RefusesControlCharacters() {
        assertFalse(VaultHttp.isValidToken("hvs.line\nbreak"));
        assertFalse(VaultHttp.isValidToken("hvs.\u007f"));
    }

    @Test
    void newHttpClient_FollowsNoRedirects_AndAsksForTls12OrLater() {
        try (var http = VaultHttp.newHttpClient()) {
            assertEquals(HttpClient.Redirect.NEVER, http.followRedirects());
            assertFalse(VaultHttp.followsRedirects(http));
            assertEquals(Duration.ofSeconds(30), http.connectTimeout().orElseThrow());
            assertEquals(List.of("TLSv1.3", "TLSv1.2"), Arrays.asList(http.sslParameters().getProtocols()));
        }
    }

    @Test
    void checkRedirects_RefusesAClientThatFollowsThem_UnlessAllowed() {
        try (var following = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.ALWAYS).build()) {
            assertTrue(VaultHttp.followsRedirects(following));
            var e = assertThrows(IllegalArgumentException.class, () -> VaultHttp.checkRedirects(following, false));
            assertTrue(e.getMessage().contains("Redirect.NEVER"));
            VaultHttp.checkRedirects(following, true);
        }
        VaultHttp.checkRedirects(null, false);
        assertThrows(NullPointerException.class, () -> VaultHttp.followsRedirects(null));
    }

    @Test
    void decryptToken_RevealsAProtectedToken_IntoAnArrayItsLength() {
        var protector = TestRings.protector();

        var token = VaultHttp.decryptToken(protector, protector.encrypt("hvs.abc"));

        assertArrayEquals("hvs.abc".toCharArray(), token);
    }

    @Test
    void decryptToken_RefusesAnythingElse_WithoutQuotingIt() {
        var protector = TestRings.protector();
        var other = TestRings.ring().createProtector(VaultClient.TOKEN_PURPOSE);

        for (var bad : new String[] {"hvs.plain-token", other.encrypt("hvs.other-ring"), TestRings.protector().encrypt("x")}) {
            var e = assertThrows(IllegalStateException.class, () -> VaultHttp.decryptToken(protector, bad));
            assertNull(e.getCause());
            assertFalse(e.getMessage().contains("plain-token"));
        }
        assertThrows(IllegalStateException.class, () -> VaultHttp.decryptToken(protector, ""));
        assertThrows(IllegalStateException.class, () -> VaultHttp.decryptToken(protector, null));
        assertThrows(IllegalStateException.class, () -> VaultHttp.decryptToken(protector, protector.encrypt("has space")));
        assertThrows(NullPointerException.class, () -> VaultHttp.decryptToken(null, "x"));
    }

    @ParameterizedTest
    @CsvSource({"200,0,0,200", "200,1,0,400", "200,2,0,800", "200,2,50,850", "200,5,0,6400", "200,6,0,10000", "200,20,0,10000",
        "200,0,100,300", "200,9,100,10100", "0,3,37,37", "10000,0,0,10000", "200,40,0,10000"})
    void retryDelay_Doubles_UpToTheMaximum_PlusTheJitter(int baseMillis, int retry, int jitter, int expectedMillis) {
        assertEquals(Duration.ofMillis(expectedMillis), VaultHttp.retryDelay(Duration.ofMillis(baseMillis), retry, jitter));
    }

    @Test
    void theLimits_AreThoseOfTheOtherPorts() {
        assertEquals(Duration.ofSeconds(10), VaultHttp.MAX_RETRY_DELAY);
        assertEquals(2048, VaultHttp.MAX_TOKEN_LENGTH);
        for (var i = 0; i < 200; i++) {
            var jitter = VaultHttp.jitterMillis();
            assertTrue(jitter >= 0 && jitter <= 100);
        }
        assertEquals(Long.MAX_VALUE, VaultHttp.saturatedNanos(Duration.ofSeconds(Long.MAX_VALUE)));
        assertEquals(5_000_000, VaultHttp.saturatedNanos(Duration.ofMillis(5)));
    }

    @ParameterizedTest
    @CsvSource({"429,true", "500,true", "502,true", "503,true", "504,true", "501,false", "400,false", "403,false", "404,false", "412,false", "200,false"})
    void isTransientStatus_IsTrueForWhatAnotherAttemptMayNotMeet(int status, boolean expected) {
        assertEquals(expected, VaultHttp.isTransientStatus(status));
        assertEquals(expected, new VaultRequestException("x", status).isTransient());
    }

    @Test
    void withRetries_RetriesTransientFailures_ThenSucceeds() {
        var attempts = new AtomicInteger();

        var result = VaultHttp.withRetries(3, Duration.ZERO, () -> false, () -> switch (attempts.incrementAndGet()) {
            case 1 -> throw new VaultRequestException("busy", 503);
            case 2 -> throw new IOException("reset");
            case 3 -> throw new UncheckedIOException(new IOException("lost"));
            default -> "done";
        }, CancellationException::new);

        assertEquals("done", result);
        assertEquals(4, attempts.get());
    }

    @Test
    void withRetries_ThrowsANonTransientRefusal_AtOnce() {
        var attempts = new AtomicInteger();
        var refused = new VaultRequestException("no", 403);

        var e = assertThrows(VaultRequestException.class, () -> VaultHttp.withRetries(3, Duration.ZERO, () -> false, () -> {
            attempts.incrementAndGet();
            throw refused;
        }, CancellationException::new));

        assertSame(refused, e);
        assertEquals(1, attempts.get());
    }

    @Test
    void withRetries_ThrowsAnythingElse_AtOnce() {
        var attempts = new AtomicInteger();
        assertThrows(ArithmeticException.class, () -> VaultHttp.withRetries(3, Duration.ZERO, () -> false, () -> {
            attempts.incrementAndGet();
            throw new ArithmeticException();
        }, CancellationException::new));
        assertEquals(1, attempts.get());
    }

    @Test
    void withRetries_OnceRetriesRunOut_ThrowsTheLastFailure() {
        var attempts = new AtomicInteger();

        var e = assertThrows(UncheckedIOException.class, () -> VaultHttp.withRetries(2, Duration.ZERO, () -> false, () -> {
            throw new IOException("attempt " + attempts.incrementAndGet());
        }, CancellationException::new));

        assertEquals("attempt 3", e.getCause().getMessage());
        var last = assertThrows(VaultRequestException.class, () -> VaultHttp.withRetries(1, Duration.ZERO, () -> false, () -> {
            throw new VaultRequestException("busy", 429);
        }, CancellationException::new));
        assertEquals(429, last.statusCode());
    }

    @Test
    void withRetries_StopsRetrying_OnceClosed() {
        var attempts = new AtomicInteger();
        assertThrows(UncheckedIOException.class, () -> VaultHttp.withRetries(10, Duration.ZERO, () -> attempts.get() >= 2, () -> {
            attempts.incrementAndGet();
            throw new IOException("x");
        }, CancellationException::new));
        assertEquals(2, attempts.get());
    }

    @Test
    void withRetries_AnInterrupt_IsACancellation() throws Exception {
        var failure = new AtomicReference<Throwable>();
        var thread = Thread.ofVirtual().start(() -> {
            try {
                VaultHttp.withRetries(3, Duration.ofSeconds(30), () -> false, () -> {
                    throw new IOException("x");
                }, () -> new CancellationException("abandoned"));
            } catch (Throwable e) {
                failure.set(e);
            }
        });
        Futures.sleep(100);
        thread.interrupt();
        thread.join();

        assertEquals("abandoned", assertInstanceOf(CancellationException.class, failure.get()).getMessage());

        failure.set(null);
        thread = Thread.ofVirtual().start(() -> {
            try {
                VaultHttp.withRetries(3, Duration.ZERO, () -> false, () -> {
                    throw new InterruptedException();
                }, () -> new CancellationException("interrupted"));
            } catch (Throwable e) {
                failure.set(e);
            }
        });
        thread.join();
        assertEquals("interrupted", failure.get().getMessage());
    }

    @Test
    void send_ReadsTheWholeResponse_WithinTheDeadline() throws Exception {
        try (var vault = new FakeVault(); var http = VaultHttp.newHttpClient()) {
            vault.then(201, "{\"ok\":true}");
            var request = HttpRequest.newBuilder(vault.address().resolve("/v1/x")).build();

            var read = VaultHttp.send(http, request, System.nanoTime() + Duration.ofSeconds(10).toNanos(),
                    response -> response.statusCode() + " " + new String(response.body().readAllBytes(), StandardCharsets.UTF_8), () -> "late");

            assertEquals("201 {\"ok\":true}", read);
        }
    }

    @Test
    void send_ABodyOutrunningTheDeadline_TimesOut() throws Exception {
        var server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            exchange.getResponseBody().write('{');
            exchange.getResponseBody().flush();
            try {
                Thread.sleep(5_000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            exchange.close();
        });
        server.start();
        try (var http = VaultHttp.newHttpClient()) {
            var request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/v1/x")).build();
            var started = System.nanoTime();

            var e = assertThrows(HttpTimeoutException.class, () -> VaultHttp.send(http, request, System.nanoTime() + Duration.ofMillis(300).toNanos(),
                    response -> response.body().readAllBytes(), () -> "the body took too long"));

            assertEquals("the body took too long", e.getMessage());
            assertTrue(Duration.ofNanos(System.nanoTime() - started).compareTo(Duration.ofSeconds(3)) < 0);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void bodyPublisher_HandsOverTheArrayItself() {
        var body = "{\"plaintext\":\"c2VjcmV0\"}xx".getBytes(StandardCharsets.UTF_8);
        var publisher = VaultHttp.bodyPublisher(body, body.length - 2);
        var buffers = new ArrayList<ByteBuffer>();
        var completed = new AtomicInteger();
        var errors = new ArrayList<Throwable>();

        publisher.subscribe(new Flow.Subscriber<>() {
            @Override
            public void onSubscribe(Flow.Subscription subscription) {
                subscription.request(1);
                subscription.request(1);
            }

            @Override
            public void onNext(ByteBuffer item) {
                buffers.add(item);
            }

            @Override
            public void onError(Throwable throwable) {
                errors.add(throwable);
            }

            @Override
            public void onComplete() {
                completed.incrementAndGet();
            }
        });

        assertEquals(body.length - 2, publisher.contentLength());
        assertEquals(1, buffers.size());
        assertSame(body, buffers.getFirst().array());
        assertEquals(body.length - 2, buffers.getFirst().remaining());
        assertEquals(1, completed.get());
        assertTrue(errors.isEmpty());
    }

    @Test
    void bodyPublisher_RefusesABadRequest_AndBadBounds() {
        var errors = new ArrayList<Throwable>();
        VaultHttp.bodyPublisher(new byte[3], 3).subscribe(new Flow.Subscriber<>() {
            @Override
            public void onSubscribe(Flow.Subscription subscription) {
                subscription.request(0);
            }

            @Override
            public void onNext(ByteBuffer item) {
                throw new AssertionError("nothing was requested");
            }

            @Override
            public void onError(Throwable throwable) {
                errors.add(throwable);
            }

            @Override
            public void onComplete() {
                throw new AssertionError("nothing was requested");
            }
        });

        assertInstanceOf(IllegalArgumentException.class, errors.getFirst());
        assertThrows(IndexOutOfBoundsException.class, () -> VaultHttp.bodyPublisher(new byte[3], 4));
        assertThrows(NullPointerException.class, () -> VaultHttp.bodyPublisher(null, 0));
    }

    @Test
    void await_ReturnsTheResult_OrFailsAsTheCallerSays() {
        assertEquals("x", VaultHttp.await(CompletableFuture.completedFuture("x"), 1_000_000_000L, IllegalStateException::new, CancellationException::new));

        var pending = new CompletableFuture<String>();
        var timedOut = assertThrows(IllegalStateException.class,
                () -> VaultHttp.await(pending, 10_000_000L, () -> new IllegalStateException("late"), CancellationException::new));
        assertEquals("late", timedOut.getMessage());
        assertTrue(pending.isCancelled());

        assertThrows(ArithmeticException.class, () -> VaultHttp.await(CompletableFuture.failedFuture(new ArithmeticException()), 1_000_000_000L,
                IllegalStateException::new, CancellationException::new));
        assertThrows(StackOverflowError.class, () -> VaultHttp.await(CompletableFuture.failedFuture(new StackOverflowError()), 1_000_000_000L,
                IllegalStateException::new, CancellationException::new));
        var io = assertThrows(UncheckedIOException.class, () -> VaultHttp.await(CompletableFuture.failedFuture(new IOException("io")), 1_000_000_000L,
                IllegalStateException::new, CancellationException::new));
        assertEquals("io", io.getCause().getMessage());
        var checked = assertThrows(CompletionException.class, () -> VaultHttp.await(CompletableFuture.failedFuture(new Exception("checked")),
                1_000_000_000L, IllegalStateException::new, CancellationException::new));
        assertEquals("checked", checked.getCause().getMessage());
    }

    @Test
    void await_AnInterrupt_CancelsTheFuture_AndRestoresTheStatus() throws Exception {
        var pending = new CompletableFuture<String>();
        var failure = new AtomicReference<Throwable>();
        var stillInterrupted = new AtomicReference<Boolean>();
        var thread = Thread.ofVirtual().start(() -> {
            try {
                VaultHttp.await(pending, Long.MAX_VALUE, IllegalStateException::new, () -> new CancellationException("interrupted"));
            } catch (Throwable e) {
                failure.set(e);
                stillInterrupted.set(Thread.currentThread().isInterrupted());
            }
        });
        Futures.sleep(100);
        thread.interrupt();
        thread.join();

        assertEquals("interrupted", failure.get().getMessage());
        assertTrue(stillInterrupted.get());
        assertTrue(pending.isCancelled());
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "{\"errors\":[\"permission denied\",\"2\"]}|permission denied;2",
        "{\"errors\":[1, {\"a\":true}]}|1;{\"a\":true}",
        "{\"errors\":[]}|''",
        "{\"data\":null}|''"})
    void readErrors_ReadsVaultsErrorList(String body, String expected) {
        var bytes = body.getBytes(StandardCharsets.UTF_8);
        assertEquals(expected.isEmpty() ? List.of() : List.of(expected.split(";")), VaultHttp.readErrors(bytes, bytes.length));
    }

    @ParameterizedTest
    @ValueSource(strings = {"{\"errors\":\"one\"}", "[\"x\"]", "<html>Bad gateway</html>", "", "{\"errors\":[]} trailing", "{\"errors\":["})
    void readErrors_IsNullForAnythingButVaultsJson(String body) {
        var bytes = body.getBytes(StandardCharsets.UTF_8);
        assertNull(VaultHttp.readErrors(bytes, bytes.length));
    }

    @Test
    void readErrors_ReadsOnlyTheLengthGiven() {
        var bytes = "{\"errors\":[\"a\"]}garbage".getBytes(StandardCharsets.UTF_8);
        assertEquals(List.of("a"), VaultHttp.readErrors(bytes, bytes.length - 7));
    }

    @ParameterizedTest
    @CsvSource({"400,' Bad Request'", "403,' Forbidden'", "503,' Service Unavailable'", "307,' Temporary Redirect'", "418,''"})
    void reasonPhrase_NamesTheCommonStatuses(int status, String expected) {
        assertEquals(expected, VaultHttp.reasonPhrase(status));
    }

    // --- Token types ---------------------------------------------------------------------------

    @Test
    void staticVaultTokenSource_CopiesItsToken_UntilClosed() {
        var tokens = new StaticVaultTokenSource(CharBuffer.wrap(FakeVault.TOKEN.toCharArray()));
        var destination = new char[VaultHttp.MAX_TOKEN_LENGTH];

        assertEquals(FakeVault.TOKEN.length(), await(tokens.copyTokenAsync(destination)));
        assertEquals(FakeVault.TOKEN, new String(destination, 0, FakeVault.TOKEN.length()));

        tokens.close();
        var zeroed = new char[VaultHttp.MAX_TOKEN_LENGTH];
        tokens.copyTokenAsync(zeroed);
        assertFalse(VaultHttp.isValidToken(CharBuffer.wrap(zeroed, 0, FakeVault.TOKEN.length())));
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "hvs.with space", "hvs.é"})
    void staticVaultTokenSource_RejectsATokenThatIsNotOne(String token) {
        assertThrows(IllegalArgumentException.class, () -> new StaticVaultTokenSource(token));
    }

    @Test
    void staticVaultTokenSource_RejectsATokenOverTheLimit_ADestinationTooSmall_AndNulls() {
        assertThrows(IllegalArgumentException.class, () -> new StaticVaultTokenSource("t".repeat(VaultHttp.MAX_TOKEN_LENGTH + 1)));
        new StaticVaultTokenSource("t".repeat(VaultHttp.MAX_TOKEN_LENGTH)).close();
        assertThrows(NullPointerException.class, () -> new StaticVaultTokenSource(null));
        try (var tokens = new StaticVaultTokenSource("hvs.abc")) {
            assertThrows(IllegalArgumentException.class, () -> tokens.copyTokenAsync(new char[3]));
            assertThrows(NullPointerException.class, () -> tokens.copyTokenAsync(null));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"", "hvs.with space", "hvs.line\nbreak", "café"})
    void staticVaultToken_Protect_RejectsATokenThatCantBeSent(String token) {
        assertThrows(IllegalArgumentException.class, () -> StaticVaultToken.protect(TestRings.protector(), token));
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" "})
    void staticVaultToken_RejectsAnEmptyProtectedToken(String protectedToken) {
        assertThrows(RuntimeException.class, () -> new StaticVaultToken(protectedToken));
    }

    @Test
    void staticVaultToken_Protect_HoldsOnlyTheProtectedToken() {
        var protector = TestRings.protector();

        var token = StaticVaultToken.protect(protector, CharBuffer.wrap("hvs.static".toCharArray()));

        assertFalse(token.toString().contains("static"));
        assertEquals(token.toString(), await(token.getTokenAsync()));
        assertEquals("hvs.static", TestRings.decrypt(protector, token.toString()));
        assertThrows(NullPointerException.class, () -> StaticVaultToken.protect(null, "hvs.x"));
        assertThrows(NullPointerException.class, () -> StaticVaultToken.protect(protector, null));
    }

    @Test
    void runAsync_FailsAsFailureTurnsIt_AndCallsAbandoned_OnAFailureOrALateSuccess() throws Exception {
        var abandoned = new java.util.concurrent.CountDownLatch(2);

        assertEquals(5, await(VaultHttp.runAsync("hkdfguard-test", () -> 5, e -> e, abandoned::countDown)));
        assertEquals(2, abandoned.getCount());

        var failed = VaultHttp.runAsync("hkdfguard-test", () -> {
            throw new IllegalStateException("failed");
        }, e -> new IOException(e.getMessage()), abandoned::countDown);
        var failure = assertThrows(java.util.concurrent.ExecutionException.class, () -> failed.get(10, java.util.concurrent.TimeUnit.SECONDS));
        assertInstanceOf(IOException.class, failure.getCause());
        assertEquals("failed", failure.getCause().getMessage());
        assertEquals(1, abandoned.getCount());

        // Cancelling interrupts the thread; work that finishes anyway is abandoned.
        var started = new java.util.concurrent.CountDownLatch(1);
        var late = VaultHttp.<Integer>runAsync("hkdfguard-test", () -> {
            started.countDown();
            try {
                new java.util.concurrent.CountDownLatch(1).await();
            } catch (InterruptedException e) {
                // Finished anyway.
            }
            return 1;
        }, e -> e, abandoned::countDown);
        started.await();
        late.cancel(true);
        assertTrue(abandoned.await(10, java.util.concurrent.TimeUnit.SECONDS));
    }

    @Test
    void newRequest_CarriesVaultsHeaders_AndWithToken_TheDecryptedToken() {
        var protector = TestRings.protector();
        var uri = URI.create("https://vault.test/v1/secret/data/a");

        var plain = VaultHttp.newRequest(uri, null, null).build();
        assertEquals(List.of("true"), plain.headers().allValues("X-Vault-Request"));
        assertTrue(plain.headers().allValues("X-Vault-Namespace").isEmpty());
        assertTrue(plain.timeout().isEmpty());

        var request = VaultHttp.withToken(VaultHttp.newRequest(uri, Duration.ofSeconds(5), "team-a"), protector,
                protector.encrypt("hvs.token")).build();
        assertEquals(List.of("team-a"), request.headers().allValues("X-Vault-Namespace"));
        assertEquals(Duration.ofSeconds(5), request.timeout().orElseThrow());
        assertEquals(List.of("hvs.token"), request.headers().allValues(VaultHttp.TOKEN_HEADER));
        assertThrows(IllegalStateException.class, () -> VaultHttp.withToken(VaultHttp.newRequest(uri, null, null), protector, "hvs.token"));
    }
}
