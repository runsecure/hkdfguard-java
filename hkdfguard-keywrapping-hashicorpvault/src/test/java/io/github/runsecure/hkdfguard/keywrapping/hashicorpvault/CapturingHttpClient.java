package io.github.runsecure.hkdfguard.keywrapping.hashicorpvault;

import java.io.IOException;
import java.net.Authenticator;
import java.net.CookieHandler;
import java.net.ProxySelector;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.Flow;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;

/**
 * An HttpClient that hands every request to a real one, after reading its body through the
 * request's own publisher and keeping the arrays behind the buffers it published - the arrays
 * java.net.http sends from - to check what became of them once the call is done.
 */
final class CapturingHttpClient extends HttpClient {
    private final HttpClient inner = HttpClient.newBuilder().followRedirects(Redirect.NEVER).build();
    private final List<byte[]> bodyArrays = Collections.synchronizedList(new ArrayList<>());
    private final List<Boolean> bodyArraysAccessible = Collections.synchronizedList(new ArrayList<>());

    /** The array behind every body buffer published, in order. */
    List<byte[]> bodyArrays() {
        synchronized (bodyArrays) {
            return List.copyOf(bodyArrays);
        }
    }

    /** Whether every body buffer published wrapped an array this client could reach. */
    boolean everyBodyArrayAccessible() {
        synchronized (bodyArraysAccessible) {
            return !bodyArraysAccessible.isEmpty() && !bodyArraysAccessible.contains(false);
        }
    }

    private void capture(HttpRequest request) {
        request.bodyPublisher().ifPresent(publisher -> publisher.subscribe(new Flow.Subscriber<>() {
            @Override
            public void onSubscribe(Flow.Subscription subscription) {
                subscription.request(Long.MAX_VALUE);
            }

            @Override
            public void onNext(ByteBuffer item) {
                var accessible = item.hasArray();
                bodyArraysAccessible.add(accessible);
                if (accessible)
                    bodyArrays.add(item.array());
            }

            @Override
            public void onError(Throwable throwable) {
            }

            @Override
            public void onComplete() {
            }
        }));
    }

    @Override
    public <T> HttpResponse<T> send(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) throws IOException, InterruptedException {
        capture(request);
        return inner.send(request, responseBodyHandler);
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler) {
        capture(request);
        return inner.sendAsync(request, responseBodyHandler);
    }

    @Override
    public <T> CompletableFuture<HttpResponse<T>> sendAsync(HttpRequest request, HttpResponse.BodyHandler<T> responseBodyHandler,
            HttpResponse.PushPromiseHandler<T> pushPromiseHandler) {
        capture(request);
        return inner.sendAsync(request, responseBodyHandler, pushPromiseHandler);
    }

    @Override
    public Optional<CookieHandler> cookieHandler() {
        return inner.cookieHandler();
    }

    @Override
    public Optional<Duration> connectTimeout() {
        return inner.connectTimeout();
    }

    @Override
    public Redirect followRedirects() {
        return inner.followRedirects();
    }

    @Override
    public Optional<ProxySelector> proxy() {
        return inner.proxy();
    }

    @Override
    public SSLContext sslContext() {
        return inner.sslContext();
    }

    @Override
    public SSLParameters sslParameters() {
        return inner.sslParameters();
    }

    @Override
    public Optional<Authenticator> authenticator() {
        return inner.authenticator();
    }

    @Override
    public Version version() {
        return inner.version();
    }

    @Override
    public Optional<Executor> executor() {
        return inner.executor();
    }

    @Override
    public void close() {
        inner.close();
    }
}
