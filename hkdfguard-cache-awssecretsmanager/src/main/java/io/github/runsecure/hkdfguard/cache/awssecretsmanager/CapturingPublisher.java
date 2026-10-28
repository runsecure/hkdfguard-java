package io.github.runsecure.hkdfguard.cache.awssecretsmanager;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.cache.SecretJsonBody;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;
import org.reactivestreams.Publisher;
import org.reactivestreams.Subscriber;
import org.reactivestreams.Subscription;

/**
 * A successful GetSecretValue response's body with the secret taken out. It reads the whole body
 * from the HTTP client into an array of its own - zeroing each buffer the client hands over, where
 * the client lets it write to one - has {@link SecretCapture} take the secret out, zeroes the array,
 * and publishes what's left as one buffer once the subscriber asks for one. The body is read from
 * the HTTP client only once the subscriber has asked for something, and only once.
 */
final class CapturingPublisher implements Publisher<ByteBuffer> {
    private static final int INITIAL_BUFFER_LENGTH = 4 * 1024;

    private final Publisher<ByteBuffer> body;
    private final SecretCapture capture;
    private final AtomicBoolean subscribed = new AtomicBoolean();

    CapturingPublisher(Publisher<ByteBuffer> body, SecretCapture capture) {
        this.body = body;
        this.capture = capture;
    }

    @Override
    public void subscribe(Subscriber<? super ByteBuffer> subscriber) {
        Objects.requireNonNull(subscriber, "subscriber");
        if (!subscribed.compareAndSet(false, true)) {
            subscriber.onSubscribe(new Subscription() {
                @Override
                public void request(long n) {
                }

                @Override
                public void cancel() {
                }
            });
            subscriber.onError(new IllegalStateException("A response body can be read only once."));
            return;
        }

        var relay = new Relay(subscriber);
        subscriber.onSubscribe(relay);
        body.subscribe(relay);
    }

    /** Zeroes what's left of buffer, unless it is read-only. */
    static void zero(ByteBuffer buffer) {
        if (buffer.isReadOnly())
            return;
        if (buffer.hasArray()) {
            Arrays.fill(buffer.array(), buffer.arrayOffset() + buffer.position(), buffer.arrayOffset() + buffer.limit(), (byte) 0);
        } else {
            for (var i = buffer.position(); i < buffer.limit(); i++)
                buffer.put(i, (byte) 0);
        }
    }

    /**
     * Subscribes to the HTTP client's body and is the SDK's subscription to the redacted one. Every
     * field is guarded by this; nothing is signalled to either side while holding it.
     */
    private final class Relay implements Subscriber<ByteBuffer>, Subscription {
        private final Subscriber<? super ByteBuffer> subscriber;

        private Subscription source;
        private boolean demanded;
        private boolean sourceRequested;
        private boolean sourceDone;
        private boolean cancelled;
        private boolean delivered;
        private ByteBuffer redacted;
        private byte[] buffer = new byte[INITIAL_BUFFER_LENGTH];
        private int length;

        Relay(Subscriber<? super ByteBuffer> subscriber) {
            this.subscriber = subscriber;
        }

        // The SDK's side.

        @Override
        public void request(long n) {
            if (n <= 0) {
                cancel();
                subscriber.onError(new IllegalArgumentException("Reactive Streams rule 3.9: request " + n + " is not positive."));
                return;
            }

            Subscription start = null;
            synchronized (this) {
                if (cancelled)
                    return;
                demanded = true;
                if (source != null && !sourceRequested) {
                    sourceRequested = true;
                    start = source;
                }
            }
            if (start != null)
                start.request(Long.MAX_VALUE);
            deliver();
        }

        @Override
        public void cancel() {
            Subscription stop;
            synchronized (this) {
                if (cancelled)
                    return;
                cancelled = true;
                stop = sourceDone ? null : source;
                redacted = null;
                clear();
            }
            if (stop != null)
                stop.cancel();
        }

        // The HTTP client's side.

        @Override
        public void onSubscribe(Subscription subscription) {
            Objects.requireNonNull(subscription, "subscription");
            var refuse = false;
            var start = false;
            synchronized (this) {
                if (source != null || cancelled) {
                    refuse = true;
                } else {
                    source = subscription;
                    start = demanded;
                    sourceRequested = start;
                }
            }
            if (refuse)
                subscription.cancel();
            else if (start)
                subscription.request(Long.MAX_VALUE);
        }

        @Override
        public void onNext(ByteBuffer chunk) {
            Objects.requireNonNull(chunk, "chunk");
            InvalidSecretDataException tooLarge = null;
            Subscription stop = null;
            synchronized (this) {
                try {
                    if (sourceDone || cancelled)
                        return;

                    var count = chunk.remaining();
                    if (count > SecretJsonBody.MAX_BODY_LENGTH - length) {
                        tooLarge = new InvalidSecretDataException("The response body is over " + SecretJsonBody.MAX_BODY_LENGTH + " bytes.");
                        sourceDone = true;
                        stop = source;
                        clear();
                    } else {
                        ensureCapacity(length + count);
                        chunk.duplicate().get(buffer, length, count);
                        length += count;
                    }
                } finally {
                    zero(chunk);
                }
            }

            if (tooLarge != null) {
                stop.cancel();
                capture.failed(tooLarge);
                subscriber.onError(tooLarge);
            }
        }

        @Override
        public void onError(Throwable error) {
            synchronized (this) {
                if (sourceDone || cancelled)
                    return;
                sourceDone = true;
                clear();
            }
            subscriber.onError(error);
        }

        @Override
        public void onComplete() {
            RuntimeException refused = null;
            synchronized (this) {
                if (sourceDone || cancelled)
                    return;
                sourceDone = true;
                try {
                    redacted = ByteBuffer.wrap(capture.capture(buffer, length));
                } catch (RuntimeException e) {
                    refused = e;
                } finally {
                    clear();
                }
            }

            if (refused != null)
                subscriber.onError(refused);
            else
                deliver();
        }

        // Publishes the redacted body once it is ready and asked for.
        private void deliver() {
            ByteBuffer next;
            synchronized (this) {
                if (!demanded || redacted == null || delivered || cancelled)
                    return;
                delivered = true;
                next = redacted;
                redacted = null;
            }
            subscriber.onNext(next);
            subscriber.onComplete();
        }

        private void ensureCapacity(int needed) {
            if (needed <= buffer.length)
                return;

            var larger = Arrays.copyOf(buffer, Math.min(Math.max(needed, buffer.length * 2), SecretJsonBody.MAX_BODY_LENGTH));
            ArrayUtility.zeroMemory(buffer);
            buffer = larger;
        }

        private void clear() {
            ArrayUtility.zeroMemory(buffer);
            length = 0;
        }
    }
}
