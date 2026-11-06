package io.github.runsecure.hkdfguard.integration.hashicorpvault;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Function;
import javax.net.ssl.SSLContext;

/**
 * Vault's HTTP API served on 127.0.0.1 (http, which the client allows on loopback; or https given
 * an SSLContext): every request is recorded as it arrives, then answered by the next queued
 * responder, or by {@link #respond} once the queue is empty.
 */
final class FakeVault implements AutoCloseable {
    static final String TOKEN = "hvs.CAESIFakeTokenForTests";

    /** An answer: a status, a body ("" for none) and any extra headers. */
    record Answer(int status, String body, Map<String, String> headers) {
        Answer(int status, String body) {
            this(status, body, Map.of());
        }

        /** No answer at all: the connection is closed. */
        static final Answer DROP = new Answer(-1, "");
    }

    /** A request as it arrived. */
    record Received(String method, URI uri, Map<String, List<String>> headers, byte[] body) {
        /** The header's values joined with ","; null if it wasn't sent. */
        String header(String name) {
            var values = headers.get(name);
            return values == null ? null : String.join(",", values);
        }

        String bodyText() {
            return body.length == 0 ? null : new String(body, StandardCharsets.UTF_8);
        }

        String pathAndQuery() {
            return uri.getRawPath() + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
        }
    }

    private final HttpServer server;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();
    private final ConcurrentLinkedQueue<Function<Received, Answer>> queued = new ConcurrentLinkedQueue<>();
    final List<Received> requests = Collections.synchronizedList(new ArrayList<>());

    /** Over https, the subject of the client certificate each request came with; "none" without one. */
    final List<String> clientCertificates = Collections.synchronizedList(new ArrayList<>());

    /** Answers a request once the queue is empty; 200 with {"data":{}} unless set. */
    volatile Function<Received, Answer> respond = r -> new Answer(200, "{\"data\":{}}");

    /** Makes each request wait this long before it's answered. */
    volatile long delayMillis;

    FakeVault() {
        this(null);
    }

    /** Served over https with tls, when given. */
    FakeVault(SSLContext tls) {
        this(tls, false);
    }

    /** Served over https with tls, requiring a client certificate if needClientAuth. */
    FakeVault(SSLContext tls, boolean needClientAuth) {
        try {
            var address = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
            if (tls == null) {
                server = HttpServer.create(address, 0);
            } else {
                var https = HttpsServer.create(address, 0);
                https.setHttpsConfigurator(new HttpsConfigurator(tls) {
                    @Override
                    public void configure(HttpsParameters parameters) {
                        var ssl = tls.getDefaultSSLParameters();
                        ssl.setNeedClientAuth(needClientAuth);
                        parameters.setSSLParameters(ssl);
                        parameters.setNeedClientAuth(needClientAuth);
                    }
                });
                server = https;
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        server.setExecutor(executor);
        server.createContext("/", this::handle);
        server.start();
    }

    /** The address to reach this fake at, e.g. http://127.0.0.1:12345. */
    URI address() {
        return URI.create((server instanceof HttpsServer ? "https" : "http") + "://127.0.0.1:" + server.getAddress().getPort());
    }

    FakeVault then(Function<Received, Answer> responder) {
        queued.add(responder);
        return this;
    }

    /** Queues an answer; headers as name, value, name, value... */
    FakeVault then(int status, String body, String... headers) {
        var map = new TreeMap<String, String>();
        for (var i = 0; i < headers.length; i += 2)
            map.put(headers[i], headers[i + 1]);
        var answer = new Answer(status, body == null ? "" : body, map);
        return then(r -> answer);
    }

    Received single() {
        assertEquals(1, requests.size(), "requests");
        return requests.getFirst();
    }

    List<Received> requests() {
        synchronized (requests) {
            return List.copyOf(requests);
        }
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            var headers = new TreeMap<String, List<String>>(String.CASE_INSENSITIVE_ORDER);
            for (var header : exchange.getRequestHeaders().entrySet())
                headers.put(header.getKey(), List.copyOf(header.getValue()));
            var body = exchange.getRequestBody().readAllBytes();
            var received = new Received(exchange.getRequestMethod(), exchange.getRequestURI(), headers, body);
            requests.add(received);
            if (exchange instanceof HttpsExchange https) {
                try {
                    clientCertificates.add(https.getSSLSession().getPeerPrincipal().getName());
                } catch (javax.net.ssl.SSLPeerUnverifiedException e) {
                    clientCertificates.add("none");
                }
            }

            if (delayMillis > 0) {
                try {
                    Thread.sleep(delayMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }

            var next = queued.poll();
            var answer = (next != null ? next : respond).apply(received);
            if (answer.status() < 0)
                return;

            for (var header : answer.headers().entrySet())
                exchange.getResponseHeaders().add(header.getKey(), header.getValue());
            var bytes = answer.body().getBytes(StandardCharsets.UTF_8);
            if (bytes.length > 0)
                exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(answer.status(), bytes.length == 0 ? -1 : bytes.length);
            if (bytes.length > 0)
                exchange.getResponseBody().write(bytes);
        }
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }
}
