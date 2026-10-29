package io.github.runsecure.hkdfguard.cache.awssecretsmanager;

import static io.github.runsecure.hkdfguard.cache.awssecretsmanager.TestRings.utf8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.KeyRing;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.cache.RemoteSecretCache;
import io.github.runsecure.hkdfguard.cache.SecretNameMatching;
import io.github.runsecure.hkdfguard.cache.SecretValueSink;
import io.github.runsecure.hkdfguard.dataencryptionkey.KeyRingImpl;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

/** The redacted response body's publisher, driven by hand on both sides. */
class CapturingPublisherTest {
    private final KeyRingImpl ring = TestRings.ring();

    @AfterEach
    void closeRing() {
        ring.close();
    }

    /** A cache whose fetch runs the test's body with a real sink. */
    private static final class SinkCache extends RemoteSecretCache {
        Consumer<SecretValueSink> onFetch;

        SinkCache(KeyRing ring) {
            super(ring, SecretNameMatching.EXACT, null);
        }

        @Override
        protected boolean isValidName(String name) {
            return true;
        }

        @Override
        protected void fetch(String name, SecretValueSink value) {
            onFetch.accept(value);
        }
    }

    /** The HTTP client's body, emitted by the test. */
    private static final class Source implements Publisher<ByteBuffer> {
        Subscriber<? super ByteBuffer> subscriber;
        long requested;
        boolean cancelled;

        @Override
        public void subscribe(Subscriber<? super ByteBuffer> subscriber) {
            this.subscriber = subscriber;
            subscriber.onSubscribe(new Subscription() {
                @Override
                public void request(long n) {
                    requested += n;
                }

                @Override
                public void cancel() {
                    cancelled = true;
                }
            });
        }

        byte[] emit(String text) {
            var chunk = utf8(text);
            subscriber.onNext(ByteBuffer.wrap(chunk));
            return chunk;
        }
    }

    /** The SDK's side: asks for nothing until told to. */
    private static final class Recorder implements Subscriber<ByteBuffer> {
        Subscription subscription;
        final List<String> received = new ArrayList<>();
        boolean completed;
        Throwable error;

        @Override
        public void onSubscribe(Subscription subscription) {
            this.subscription = subscription;
        }

        @Override
        public void onNext(ByteBuffer buffer) {
            var bytes = new byte[buffer.remaining()];
            buffer.get(bytes);
            received.add(new String(bytes, StandardCharsets.UTF_8));
        }

        @Override
        public void onError(Throwable error) {
            this.error = error;
        }

        @Override
        public void onComplete() {
            completed = true;
        }
    }

    @Test
    void theBodyIsReadOnlyOnceAskedFor_ThenTheRedactedBodyIsPublishedWhole_AndEveryChunkIsZeroed() {
        var cache = new SinkCache(ring);
        var source = new Source();
        var recorder = new Recorder();
        cache.onFetch = sink -> {
            new CapturingPublisher(source, new SecretCapture(sink)).subscribe(recorder);
            assertEquals(0, source.requested);

            recorder.subscription.request(1);
            assertEquals(Long.MAX_VALUE, source.requested);

            var first = source.emit("{\"Name\":\"n\",\"Secret");
            var second = source.emit("String\":\"s3cret\"}");
            assertArrayEquals(new byte[first.length], first);
            assertArrayEquals(new byte[second.length], second);
            assertTrue(recorder.received.isEmpty());

            source.subscriber.onComplete();
            assertEquals(List.of("{\"Name\":\"n\",\"SecretString\":\"\"}"), recorder.received);
            assertTrue(recorder.completed);
        };

        var result = new byte[16];
        assertEquals("s3cret", TestRings.text(result, cache.decrypt("item", result)));
    }

    @Test
    void aBodyCompletedBeforeItIsAskedFor_IsHeldUntilThen() {
        var cache = new SinkCache(ring);
        var source = new Source();
        var recorder = new Recorder();
        cache.onFetch = sink -> {
            // A source that sends regardless of demand: the redacted body still waits for it.
            new CapturingPublisher(source, new SecretCapture(sink)).subscribe(recorder);
            source.emit("{\"SecretString\":\"v\"}");
            source.subscriber.onComplete();
            assertTrue(recorder.received.isEmpty());
            assertFalse(recorder.completed);

            recorder.subscription.request(1);
            assertEquals(List.of("{\"SecretString\":\"\"}"), recorder.received);
            assertTrue(recorder.completed);
        };

        assertEquals(1, cache.decrypt("item", new byte[16]));
    }

    @Test
    void cancelling_CancelsTheSource_AndDropsWhatComesAfter() {
        var source = new Source();
        var recorder = new Recorder();
        new CapturingPublisher(source, new SecretCapture(null)).subscribe(recorder);
        recorder.subscription.request(1);
        source.emit("{\"SecretString\":\"par");

        recorder.subscription.cancel();
        assertTrue(source.cancelled);

        var late = source.emit("tial\"}");
        source.subscriber.onComplete();
        assertArrayEquals(new byte[late.length], late);
        assertTrue(recorder.received.isEmpty());
        assertFalse(recorder.completed);
        assertNull(recorder.error);
    }

    @Test
    void aNonPositiveRequest_FailsAndCancelsTheSource() {
        var source = new Source();
        var recorder = new Recorder();
        new CapturingPublisher(source, new SecretCapture(null)).subscribe(recorder);

        recorder.subscription.request(0);

        assertInstanceOf(IllegalArgumentException.class, recorder.error);
        assertTrue(source.cancelled);
    }

    @Test
    void aSourceFailure_PassesThrough() {
        var source = new Source();
        var recorder = new Recorder();
        new CapturingPublisher(source, new SecretCapture(null)).subscribe(recorder);
        recorder.subscription.request(1);
        source.emit("{\"Secret");

        var failure = new IllegalStateException("connection reset");
        source.subscriber.onError(failure);

        assertSame(failure, recorder.error);
        assertTrue(recorder.received.isEmpty());
    }

    @Test
    void aBodyOverTheLimit_IsRefused_AndTheSourceCancelled() {
        var source = new Source();
        var recorder = new Recorder();
        var capture = new SecretCapture(null);
        new CapturingPublisher(source, capture).subscribe(recorder);
        recorder.subscription.request(1);

        source.subscriber.onNext(ByteBuffer.allocate(io.github.runsecure.hkdfguard.cache.SecretJsonBody.MAX_BODY_LENGTH));
        assertNull(recorder.error);
        var over = ByteBuffer.wrap(new byte[] {1});
        source.subscriber.onNext(over);

        assertInstanceOf(InvalidSecretDataException.class, recorder.error);
        assertSame(recorder.error, capture.failure());
        assertTrue(source.cancelled);
        assertEquals(0, over.get(0));
    }

    @Test
    void aReadOnlyChunk_IsReadButLeftAsItIs() {
        var source = new Source();
        var recorder = new Recorder();
        new CapturingPublisher(source, new SecretCapture(null)).subscribe(recorder);
        recorder.subscription.request(1);

        var chunk = utf8("{\"Secret");
        source.subscriber.onNext(ByteBuffer.wrap(chunk).asReadOnlyBuffer());

        assertArrayEquals(utf8("{\"Secret"), chunk);
        assertNull(recorder.error);
    }

    @Test
    void aSecondSubscriber_IsRefused() {
        var publisher = new CapturingPublisher(new Source(), new SecretCapture(null));
        publisher.subscribe(new Recorder());

        var second = new Recorder();
        publisher.subscribe(second);

        assertInstanceOf(IllegalStateException.class, second.error);
    }
}
