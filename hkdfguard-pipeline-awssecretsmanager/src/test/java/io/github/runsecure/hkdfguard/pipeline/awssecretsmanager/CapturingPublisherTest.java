package io.github.runsecure.hkdfguard.pipeline.awssecretsmanager;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.pipeline.ResponseBody;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

/**
 * The publisher handing the SDK "{}" in place of the response body, driven by hand on both sides, as
 * hkdfguard-cache-awssecretsmanager's own is tested.
 */
class CapturingPublisherTest {
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
            var chunk = text.getBytes(StandardCharsets.UTF_8);
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

    /** Records each body the capture is handed, as it was handed over. */
    private static PipelineSecretCapture recording(List<String> captured) {
        return new PipelineSecretCapture((body, length) -> captured.add(new String(body, 0, length, StandardCharsets.UTF_8)));
    }

    @Test
    void theBodyIsReadOnlyOnceAskedFor_ThenCaptured_AndAnEmptyObjectPublished_AndEveryChunkIsZeroed() {
        var captured = new ArrayList<String>();
        var source = new Source();
        var recorder = new Recorder();
        new CapturingPublisher(source, recording(captured)).subscribe(recorder);
        assertEquals(0, source.requested);

        recorder.subscription.request(1);
        assertEquals(Long.MAX_VALUE, source.requested);

        var first = source.emit("{\"Name\":\"n\",\"Secret");
        var second = source.emit("String\":\"s3cret\"}");
        assertArrayEquals(new byte[first.length], first);
        assertArrayEquals(new byte[second.length], second);
        assertTrue(recorder.received.isEmpty());

        source.subscriber.onComplete();
        assertEquals(List.of("{\"Name\":\"n\",\"SecretString\":\"s3cret\"}"), captured);
        assertEquals(List.of("{}"), recorder.received);
        assertTrue(recorder.completed);
    }

    @Test
    void aBodyCompletedBeforeItIsAskedFor_IsHeldUntilThen() {
        var source = new Source();
        var recorder = new Recorder();

        // A source that sends regardless of demand: the empty object still waits for it.
        new CapturingPublisher(source, recording(new ArrayList<>())).subscribe(recorder);
        source.emit("{\"SecretString\":\"v\"}");
        source.subscriber.onComplete();
        assertTrue(recorder.received.isEmpty());
        assertFalse(recorder.completed);

        recorder.subscription.request(1);
        assertEquals(List.of("{}"), recorder.received);
        assertTrue(recorder.completed);
    }

    @Test
    void aCaptureThatRefusesTheBody_FailsIt() {
        var refusal = new InvalidSecretDataException("refused");
        var capture = new PipelineSecretCapture((body, length) -> {
            throw refusal;
        });
        var source = new Source();
        var recorder = new Recorder();
        new CapturingPublisher(source, capture).subscribe(recorder);
        recorder.subscription.request(1);
        source.emit("{}");

        source.subscriber.onComplete();

        assertSame(refusal, recorder.error);
        assertSame(refusal, capture.failure());
        assertTrue(capture.captured());
    }

    @Test
    void cancelling_CancelsTheSource_AndDropsWhatComesAfter() {
        var captured = new ArrayList<String>();
        var source = new Source();
        var recorder = new Recorder();
        new CapturingPublisher(source, recording(captured)).subscribe(recorder);
        recorder.subscription.request(1);
        source.emit("{\"SecretString\":\"par");

        recorder.subscription.cancel();
        assertTrue(source.cancelled);

        var late = source.emit("tial\"}");
        source.subscriber.onComplete();
        assertArrayEquals(new byte[late.length], late);
        assertTrue(captured.isEmpty());
        assertTrue(recorder.received.isEmpty());
        assertFalse(recorder.completed);
        assertNull(recorder.error);
    }

    @Test
    void aNonPositiveRequest_FailsAndCancelsTheSource() {
        var source = new Source();
        var recorder = new Recorder();
        new CapturingPublisher(source, recording(new ArrayList<>())).subscribe(recorder);

        recorder.subscription.request(0);

        assertInstanceOf(IllegalArgumentException.class, recorder.error);
        assertTrue(source.cancelled);
    }

    @Test
    void aSourceFailure_PassesThrough() {
        var source = new Source();
        var recorder = new Recorder();
        new CapturingPublisher(source, recording(new ArrayList<>())).subscribe(recorder);
        recorder.subscription.request(1);
        source.emit("{\"Secret");

        var failure = new IllegalStateException("connection reset");
        source.subscriber.onError(failure);

        assertSame(failure, recorder.error);
        assertTrue(recorder.received.isEmpty());
    }

    @Test
    void aBodyOfTheLimitOrMore_IsRefused_AndTheSourceCancelled() {
        var source = new Source();
        var recorder = new Recorder();
        var capture = recording(new ArrayList<>());
        new CapturingPublisher(source, capture).subscribe(recorder);
        recorder.subscription.request(1);

        source.subscriber.onNext(ByteBuffer.allocate(ResponseBody.MAX_LENGTH - 1));
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
        new CapturingPublisher(source, recording(new ArrayList<>())).subscribe(recorder);
        recorder.subscription.request(1);

        var chunk = "{\"Secret".getBytes(StandardCharsets.UTF_8);
        source.subscriber.onNext(ByteBuffer.wrap(chunk).asReadOnlyBuffer());

        assertArrayEquals("{\"Secret".getBytes(StandardCharsets.UTF_8), chunk);
        assertNull(recorder.error);
    }

    @Test
    void aSecondSubscriber_IsRefused() {
        var publisher = new CapturingPublisher(new Source(), recording(new ArrayList<>()));
        publisher.subscribe(new Recorder());

        var second = new Recorder();
        publisher.subscribe(second);

        assertInstanceOf(IllegalStateException.class, second.error);
    }
}
