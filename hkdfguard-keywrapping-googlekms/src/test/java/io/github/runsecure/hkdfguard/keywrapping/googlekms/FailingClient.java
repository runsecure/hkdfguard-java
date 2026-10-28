package io.github.runsecure.hkdfguard.keywrapping.googlekms;

import com.google.api.core.ApiFuture;
import com.google.api.core.ApiFutures;
import com.google.api.gax.rpc.ApiCallContext;
import com.google.api.gax.rpc.UnaryCallable;
import com.google.cloud.kms.v1.DecryptRequest;
import com.google.cloud.kms.v1.DecryptResponse;
import com.google.cloud.kms.v1.EncryptRequest;
import com.google.cloud.kms.v1.EncryptResponse;
import com.google.cloud.kms.v1.KeyManagementServiceClient;
import com.google.cloud.kms.v1.stub.KeyManagementServiceStub;
import java.util.concurrent.TimeUnit;

/**
 * A {@link KeyManagementServiceClient} over a stub whose Encrypt and Decrypt fail on the client
 * side, before any request is sent: what an application's own client could do that the fake Cloud
 * KMS, behind a real client, can't - fail with something other than the client's ApiException, or
 * throw instead of returning a future.
 */
final class FailingClient {
    private FailingClient() {
    }

    /** A client whose calls return a future failed with {@code error}. */
    static KeyManagementServiceClient failingWith(Throwable error) {
        return KeyManagementServiceClient.create(new Stub(false, error));
    }

    /** A client whose calls throw {@code error} instead of returning a future. */
    static KeyManagementServiceClient throwing(RuntimeException error) {
        return KeyManagementServiceClient.create(new Stub(true, error));
    }

    /** A client whose calls return no future at all. */
    static KeyManagementServiceClient returningNoFuture() {
        return KeyManagementServiceClient.create(new Stub(true, null));
    }

    private static final class Stub extends KeyManagementServiceStub {
        private final boolean thrown;
        private final Throwable error;

        Stub(boolean thrown, Throwable error) {
            this.thrown = thrown;
            this.error = error;
        }

        @Override
        public UnaryCallable<EncryptRequest, EncryptResponse> encryptCallable() {
            return new Failing<>();
        }

        @Override
        public UnaryCallable<DecryptRequest, DecryptResponse> decryptCallable() {
            return new Failing<>();
        }

        @Override
        public void close() {
        }

        @Override
        public void shutdown() {
        }

        @Override
        public boolean isShutdown() {
            return false;
        }

        @Override
        public boolean isTerminated() {
            return false;
        }

        @Override
        public void shutdownNow() {
        }

        @Override
        public boolean awaitTermination(long duration, TimeUnit unit) {
            return true;
        }

        private final class Failing<Q, R> extends UnaryCallable<Q, R> {
            @Override
            public ApiFuture<R> futureCall(Q request, ApiCallContext context) {
                if (!thrown)
                    return ApiFutures.immediateFailedFuture(error);
                if (error == null)
                    return null;
                throw (RuntimeException) error;
            }
        }
    }
}
