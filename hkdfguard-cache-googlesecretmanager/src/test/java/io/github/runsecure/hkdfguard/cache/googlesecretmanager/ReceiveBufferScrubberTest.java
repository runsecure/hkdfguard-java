package io.github.runsecure.hkdfguard.cache.googlesecretmanager;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.cloud.secretmanager.v1.AccessSecretVersionResponse;
import com.google.cloud.secretmanager.v1.SecretManagerServiceGrpc;
import com.google.cloud.secretmanager.v1.SecretPayload;
import com.google.protobuf.ByteString;
import io.grpc.CallOptions;
import io.grpc.Channel;
import io.grpc.ClientCall;
import io.grpc.MethodDescriptor;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** The scrubbing response marshaller, driven directly with the streams a transport would hand it. */
class ReceiveBufferScrubberTest {
    private static final MethodDescriptor<?, AccessSecretVersionResponse> ACCESS = SecretManagerServiceGrpc.getAccessSecretVersionMethod();

    private static AccessSecretVersionResponse response(int payloadLength) {
        var data = new byte[payloadLength];
        for (var i = 0; i < data.length; i++)
            data[i] = (byte) (i % 251 + 1);
        return AccessSecretVersionResponse.newBuilder()
                .setName("projects/1/secrets/s/versions/1")
                .setPayload(SecretPayload.newBuilder().setData(ByteString.copyFrom(data)))
                .build();
    }

    // The method as the scrubber passes it on to the channel.
    private static <ReqT, RespT> MethodDescriptor<ReqT, RespT> intercepted(MethodDescriptor<ReqT, RespT> method) {
        var channel = new CapturingChannel();
        new ReceiveBufferScrubber().interceptCall(method, CallOptions.DEFAULT, channel);
        @SuppressWarnings("unchecked")
        var passedOn = (MethodDescriptor<ReqT, RespT>) channel.method;
        return passedOn;
    }

    private static void assertZeroed(byte[] buffer) {
        for (var b : buffer)
            assertEquals(0, b);
    }

    @Test
    void aStreamReportingItsLength_IsReadIntoOneExactBuffer_ThatIsZeroedOnceParsed() {
        var expected = response(100);
        var stream = new RecordingStream(expected.toByteArray(), true);

        var parsed = intercepted(ACCESS).parseResponse(stream);

        assertEquals(expected, parsed);
        assertEquals(1, stream.buffers.size());
        assertEquals(expected.getSerializedSize(), stream.buffers.get(0).length);
        assertZeroed(stream.buffers.get(0));
    }

    @Test
    void aStreamNotReportingItsLength_IsReadIntoGrowingBuffers_EveryOneZeroed() {
        var expected = response(20_000);
        var stream = new RecordingStream(expected.toByteArray(), false);

        var parsed = intercepted(ACCESS).parseResponse(stream);

        assertEquals(expected, parsed);
        assertTrue(stream.buffers.size() > 1);
        stream.buffers.forEach(ReceiveBufferScrubberTest::assertZeroed);
    }

    @Test
    void theParsedPayload_IsACopy_UntouchedByZeroingTheBuffer() {
        var expected = response(64);
        var parsed = intercepted(ACCESS).parseResponse(new RecordingStream(expected.toByteArray(), true));

        assertArrayEquals(expected.getPayload().getData().toByteArray(), parsed.getPayload().getData().toByteArray());
    }

    @Test
    void anEmptyMessage_ParsesAsTheDefaultInstance() {
        var parsed = intercepted(ACCESS).parseResponse(new RecordingStream(new byte[0], true));

        assertEquals(AccessSecretVersionResponse.getDefaultInstance(), parsed);
    }

    @Test
    void malformedBytes_FailAsAnInternalStatus_AndTheBufferIsStillZeroed() {
        var stream = new RecordingStream(new byte[] {(byte) 0x0A, (byte) 0x7F, 1, 2, 3}, true);

        var e = assertThrows(StatusRuntimeException.class, () -> intercepted(ACCESS).parseResponse(stream));

        assertEquals(Status.Code.INTERNAL, e.getStatus().getCode());
        assertZeroed(stream.buffers.get(0));
    }

    @Test
    void theReplacementMarshaller_StillNamesTheMessagePrototypeAndClass() {
        var marshaller = assertInstanceOf(MethodDescriptor.PrototypeMarshaller.class, intercepted(ACCESS).getResponseMarshaller());

        assertSame(AccessSecretVersionResponse.getDefaultInstance(), marshaller.getMessagePrototype());
        assertEquals(AccessSecretVersionResponse.class, marshaller.getMessageClass());
    }

    @Test
    void aMethodWhoseMarshallerNamesNoPrototype_IsLeftAsItIs() {
        var plain = new MethodDescriptor.Marshaller<String>() {
            @Override
            public InputStream stream(String value) {
                return new ByteArrayInputStream(new byte[0]);
            }

            @Override
            public String parse(InputStream stream) {
                return "";
            }
        };
        var method = MethodDescriptor.<String, String>newBuilder()
                .setType(MethodDescriptor.MethodType.UNARY)
                .setFullMethodName("test.Service/Call")
                .setRequestMarshaller(plain)
                .setResponseMarshaller(plain)
                .build();

        assertSame(method, intercepted(method));
    }

    private static final class CapturingChannel extends Channel {
        MethodDescriptor<?, ?> method;

        @Override
        public <ReqT, RespT> ClientCall<ReqT, RespT> newCall(MethodDescriptor<ReqT, RespT> method, CallOptions options) {
            this.method = method;
            return null;
        }

        @Override
        public String authority() {
            return "test";
        }
    }

    // Serves bytes, a few at a time, recording every array it is asked to read into.
    private static final class RecordingStream extends InputStream {
        final List<byte[]> buffers = new ArrayList<>();
        private final byte[] data;
        private final boolean reportsLength;
        private int position;

        RecordingStream(byte[] data, boolean reportsLength) {
            this.data = data;
            this.reportsLength = reportsLength;
        }

        @Override
        public int available() {
            return reportsLength ? data.length - position : 0;
        }

        @Override
        public int read() {
            return position < data.length ? data[position++] & 0xFF : -1;
        }

        @Override
        public int read(byte[] buffer, int offset, int length) {
            if (buffers.stream().noneMatch(b -> b == buffer))
                buffers.add(buffer);
            if (position >= data.length)
                return -1;
            var count = Math.min(Math.min(length, 1000), data.length - position);
            System.arraycopy(data, position, buffer, offset, count);
            position += count;
            return count;
        }
    }
}
