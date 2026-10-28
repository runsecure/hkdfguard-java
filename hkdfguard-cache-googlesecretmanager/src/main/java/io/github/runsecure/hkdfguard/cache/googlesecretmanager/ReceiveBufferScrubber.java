package io.github.runsecure.hkdfguard.cache.googlesecretmanager;

import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.MessageLite;
import com.google.protobuf.Parser;
import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.ClientInterceptor;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

/**
 * Parses each response message from a buffer it owns, and zeroes that buffer once the message has
 * been parsed. gRPC's own protobuf marshaller (ProtoLiteUtils, in grpc-protobuf-lite) reads every
 * message of up to 4 MiB whose length it knows - every message off the network - into a byte array
 * held in a thread-local and reused, never cleared, for the next message parsed on that thread, so a
 * secret payload would otherwise stay there, on whichever of gRPC's threads parsed it, until some
 * later message happened to overwrite it. Parsing copies the payload out (into the ByteString the
 * cache then zeroes) - aliasing is off for a parse from an array - so clearing the buffer afterwards
 * loses nothing.
 * <p>
 * It replaces the response marshaller of any method whose marshaller names its message prototype,
 * as every generated protobuf method's does; other methods are left as they are. The message is read
 * with one read sized to the length the stream reports, which lets gRPC's in-process transport
 * serialize straight into the buffer rather than into an intermediate array of its own. What can't
 * be reached is below this marshaller: the transport's own receive buffers (Netty's pooled buffers,
 * TLS decryption).
 */
final class ReceiveBufferScrubber implements ClientInterceptor {
    // For a stream that doesn't report its length; the buffer doubles from here.
    private static final int INITIAL_BUFFER_LENGTH = 4096;

    private static final int MAX_BUFFER_LENGTH = Integer.MAX_VALUE - 8;

    @Override
    public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(MethodDescriptor<ReqT, RespT> method, CallOptions callOptions, Channel next) {
        if (method.getResponseMarshaller() instanceof MethodDescriptor.PrototypeMarshaller<RespT> marshaller
                && marshaller.getMessagePrototype() instanceof MessageLite prototype)
            method = method.toBuilder().setResponseMarshaller(new Scrubbing<>(marshaller, prototype.getParserForType())).build();
        return next.newCall(method, callOptions);
    }

    /** The original marshaller, but parsing from a buffer of its own that it zeroes afterwards. */
    private static final class Scrubbing<T> implements MethodDescriptor.PrototypeMarshaller<T> {
        private final MethodDescriptor.PrototypeMarshaller<T> original;
        private final Parser<?> parser;

        Scrubbing(MethodDescriptor.PrototypeMarshaller<T> original, Parser<?> parser) {
            this.original = original;
            this.parser = parser;
        }

        @Override
        public InputStream stream(T value) {
            return original.stream(value);
        }

        @Override
        public T getMessagePrototype() {
            return original.getMessagePrototype();
        }

        @Override
        public Class<T> getMessageClass() {
            return original.getMessageClass();
        }

        // The parser is the prototype's own, so it produces a T.
        @SuppressWarnings("unchecked")
        @Override
        public T parse(InputStream stream) {
            byte[] buffer = null;
            try {
                var available = stream.available();
                buffer = new byte[available > 0 ? available : INITIAL_BUFFER_LENGTH];
                var length = 0;
                while (true) {
                    if (length == buffer.length) {
                        // Full, which is the end when the stream reported its length; otherwise grow,
                        // zeroing what is left behind.
                        var next = stream.read();
                        if (next < 0)
                            break;
                        if (buffer.length == MAX_BUFFER_LENGTH)
                            throw Status.RESOURCE_EXHAUSTED.withDescription("The response message is too large.").asRuntimeException();
                        var grown = Arrays.copyOf(buffer, (int) Math.min(buffer.length * 2L, MAX_BUFFER_LENGTH));
                        ArrayUtility.zeroMemory(buffer);
                        buffer = grown;
                        buffer[length++] = (byte) next;
                        continue;
                    }

                    var read = stream.read(buffer, length, buffer.length - length);
                    if (read < 0)
                        break;
                    length += read;
                }
                return (T) parser.parseFrom(buffer, 0, length);
            } catch (InvalidProtocolBufferException e) {
                throw Status.INTERNAL.withDescription("Invalid protobuf byte sequence").withCause(e).asRuntimeException();
            } catch (IOException e) {
                throw Status.INTERNAL.withDescription("The response message could not be read.").withCause(e).asRuntimeException();
            } finally {
                if (buffer != null)
                    ArrayUtility.zeroMemory(buffer);
            }
        }
    }
}
