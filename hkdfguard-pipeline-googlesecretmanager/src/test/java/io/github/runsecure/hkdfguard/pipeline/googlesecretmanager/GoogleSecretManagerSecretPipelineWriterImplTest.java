package io.github.runsecure.hkdfguard.pipeline.googlesecretmanager;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.api.gax.core.NoCredentialsProvider;
import com.google.api.gax.grpc.GrpcTransportChannel;
import com.google.api.gax.rpc.ApiException;
import com.google.api.gax.rpc.FixedTransportChannelProvider;
import com.google.cloud.secretmanager.v1.SecretManagerServiceSettings;
import com.google.protobuf.ByteString;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.PipelineDataProtector;
import io.github.runsecure.hkdfguard.abstractions.SecretPipelineWriter;
import io.github.runsecure.hkdfguard.cache.InvalidSecretDataException;
import io.github.runsecure.hkdfguard.pipeline.contract.SecretPipelineWriterContractTest;
import io.grpc.Status;
import io.grpc.inprocess.InProcessChannelBuilder;
import java.io.IOException;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The writer's contract, and what only it does, against an in-process fake Secret Manager, through a
 * real SecretManagerServiceClient whose channel carries the ReceiveBufferScrubber.
 */
class GoogleSecretManagerSecretPipelineWriterImplTest extends SecretPipelineWriterContractTest {
    private final FakeSecretManager google = new FakeSecretManager();

    @AfterEach
    void closeGoogle() throws InterruptedException {
        google.close();
    }

    // No key ring anywhere: the only key is the protector's.
    @Override
    protected SecretPipelineWriter createWriter(PipelineDataProtector protector, List<String> secretNames) {
        return create(protector, secretNames);
    }

    @Override
    protected void setText(String name, String text) {
        google.set(name, text);
    }

    @Override
    protected void setKeys(String name, String json) {
        google.set(name, json);
    }

    @Override
    protected void failReads() {
        google.failure = FakeSecretManager.error(Status.Code.PERMISSION_DENIED, "Denied in a test.");
    }

    @Override
    protected Class<? extends Throwable> readFailure() {
        return ApiException.class;
    }

    @Override
    protected List<String> reads() {
        return google.gets();
    }

    private GoogleSecretManagerSecretPipelineWriterImpl create(PipelineDataProtector protector, List<String> secretNames) {
        return new GoogleSecretManagerSecretPipelineWriterImpl(google.client(), FakeSecretManager.PROJECT_ID, protector, secretNames);
    }

    private static void assertZeroed(byte[] bytes) {
        assertArrayEquals(new byte[bytes.length], bytes);
    }

    private static void assertZeroed(ByteString bytes) {
        assertZeroed(bytes.toByteArray());
    }

    @Test
    void eachSecretsLatestVersion_IsRead() {
        google.set("api-key", "value");
        try (var writer = create(protector, List.of("api-key"))) {
            pull(writer);

            assertEquals(List.of("projects/hkdfguard-test/secrets/api-key/versions/latest"), google.accesses);
            assertTrue(google.unexpectedCalls.isEmpty());
        }
    }

    @Test
    void aNameWithoutAKey_ReadsTheWholePayload() {
        google.set("db_login", "{\"user\":\"app\"}");
        try (var writer = create(protector, List.of("db_login", "db_login#user"))) {
            pull(writer);

            assertEquals("{\"user\":\"app\"}", decrypt(writer.getProtectedSecrets().get("db_login"), "db_login"));
            assertEquals("app", decrypt(writer.getProtectedSecrets().get("db_login__user"), "db_login__user"));
        }
    }

    @Test
    void theParsedPayload_AndGrpcsReceiveBuffer_AreZeroed() {
        google.set("item", "s3cret");
        try (var writer = create(protector, List.of("item"))) {
            pull(writer);

            assertEquals(1, google.responses.size());
            assertZeroed(google.responses.get(0).getPayload().getData());
            assertEquals(1, google.receiveBuffers.size());
            assertZeroed(google.receiveBuffers.get(0));
        }
    }

    @Test
    void theSynchronousRead_ReadsAndZeroesTheSame() {
        google.set("item", "s3cret");
        try (var writer = create(protector, List.of("item", "absent"))) {
            var values = new java.util.TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);
            var requests = List.of(new io.github.runsecure.hkdfguard.pipeline.SecretRequest("item", null, "item"));

            writer.readSecret("item", requests, values);
            writer.readSecret("absent", requests, values);

            assertEquals("s3cret", decrypt(values.get("item"), "item"));
            assertEquals(1, values.size());
            assertZeroed(google.responses.get(0).getPayload().getData());
        }
    }

    @Test
    void aPayloadThatIsntUtf8Text_IsRefused_AndZeroed() {
        google.set("binary", new byte[] {(byte) 0xFF, (byte) 0xFE, 0x00, (byte) 0x80});
        try (var writer = create(protector, List.of("binary"))) {
            assertPullFails(InvalidSecretDataException.class, writer);

            assertTrue(writer.getProtectedSecrets().isEmpty());
            assertZeroed(google.responses.get(0).getPayload().getData());
        }
    }

    @Test
    void aPayloadNotMatchingItsChecksum_IsRefused_AndZeroed() {
        google.set("item", "s3cret");
        google.tamper = r -> r.toBuilder().setPayload(r.getPayload().toBuilder().setDataCrc32C(r.getPayload().getDataCrc32C() ^ 1)).build();
        try (var writer = create(protector, List.of("item"))) {
            assertPullFails(CryptographicException.class, writer);

            assertTrue(writer.getProtectedSecrets().isEmpty());
            assertZeroed(google.responses.get(0).getPayload().getData());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"projects/123456789012/secrets/other/versions/1", "not a resource name"})
    void aResponseForAnotherSecret_IsRefused(String name) {
        google.set("item", "s3cret");
        google.tamper = r -> r.toBuilder().setName(name).build();
        try (var writer = create(protector, List.of("item"))) {
            assertPullFails(CryptographicException.class, writer);
        }
    }

    @Test
    void aResponseWithoutAPayload_HoldsNothing_AndOneWithoutAChecksum_IsAccepted() {
        google.set("none", "x");
        google.set("unchecked", "s3cret");
        google.tamper = r -> r.getName().contains("/none/")
                ? r.toBuilder().clearPayload().build()
                : r.toBuilder().setPayload(r.getPayload().toBuilder().clearDataCrc32C()).build();
        try (var writer = create(protector, List.of("none", "unchecked"))) {
            assertPullFails(NoSuchElementException.class, writer);

            assertEquals("s3cret", decrypt(writer.getProtectedSecrets().get("unchecked"), "unchecked"));
        }
    }

    @Test
    void create_AndTheSettingsConstructor_RejectAnInvalidProject_BeforeCreatingAClient() {
        // No credentials are looked up: the project is checked first.
        assertThrows(IllegalArgumentException.class, () -> GoogleSecretManagerSecretPipelineWriterImpl.create("bad/project", protector, List.of("item")));
        assertThrows(NullPointerException.class, () -> GoogleSecretManagerSecretPipelineWriterImpl.create("p", null, List.of("item")));
        assertThrows(NullPointerException.class,
                () -> new GoogleSecretManagerSecretPipelineWriterImpl((SecretManagerServiceSettings) null, "p", protector, List.of("item")));
    }

    @Test
    void theSettingsConstructor_RefusesATransportItCantAddTheScrubberTo() throws IOException {
        var channel = InProcessChannelBuilder.forName("unused").build();
        try {
            var fixed = SecretManagerServiceSettings.newBuilder()
                    .setTransportChannelProvider(FixedTransportChannelProvider.create(GrpcTransportChannel.create(channel)))
                    .setCredentialsProvider(NoCredentialsProvider.create())
                    .build();
            assertThrows(IllegalArgumentException.class,
                    () -> new GoogleSecretManagerSecretPipelineWriterImpl(fixed, FakeSecretManager.PROJECT_ID, protector, List.of("item")));
        } finally {
            channel.shutdownNow();
        }
    }

    @Test
    void theSettingsConstructor_MakesAndClosesItsOwnClient_WithoutCallingGoogleUntilAPull() throws IOException {
        var settings = SecretManagerServiceSettings.newBuilder().setCredentialsProvider(NoCredentialsProvider.create()).build();

        var writer = new GoogleSecretManagerSecretPipelineWriterImpl(settings, FakeSecretManager.PROJECT_ID, protector, List.of("item"));
        writer.close();
    }

    // Over gRPC's real (Netty) transport on a loopback port: the scrubber is added to the channel the
    // settings' provider builds, after the channel configurator already set (plaintext here: without
    // it the call would fail).
    @Test
    void theSettingsConstructor_AddsTheScrubber_KeepingTheChannelConfigurator() throws Exception {
        google.set("item", "value");
        var server = google.serveOnLoopback();
        var configured = new AtomicInteger();
        try {
            var provider = SecretManagerServiceSettings.defaultGrpcTransportProviderBuilder()
                    .setEndpoint("127.0.0.1:" + server.getPort())
                    .setChannelConfigurator(builder -> {
                        configured.incrementAndGet();
                        return builder.usePlaintext();
                    })
                    .setInterceptorProvider(() -> List.of(google.receiveRecorder()))
                    .build();
            var settings = SecretManagerServiceSettings.newBuilder()
                    .setTransportChannelProvider(provider)
                    .setCredentialsProvider(NoCredentialsProvider.create())
                    .build();

            try (var writer = new GoogleSecretManagerSecretPipelineWriterImpl(settings, FakeSecretManager.PROJECT_ID, protector, List.of("item"))) {
                pull(writer);
                assertEquals("value", decrypt(writer.getProtectedSecrets().get("item"), "item"));
            }

            assertTrue(configured.get() > 0);
            assertEquals(1, google.receiveBuffers.size());
            assertZeroed(google.receiveBuffers.get(0));
        } finally {
            server.shutdownNow();
            server.awaitTermination(5, TimeUnit.SECONDS);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"prod/app", "db.login"})
    void anIdSecretManagerCantHold_IsRefused(String secretName) {
        assertThrows(IllegalArgumentException.class, () -> create(protector, List.of(secretName)));
    }

    @Test
    void isValidSecretName_IsSecretManagersRule() {
        assertTrue(GoogleSecretManagerSecretPipelineWriterImpl.isValidSecretName("db_login-2"));
        assertTrue(GoogleSecretManagerSecretPipelineWriterImpl.isValidSecretName("a".repeat(GoogleSecretManagerSecretPipelineWriterImpl.MAX_SECRET_NAME_LENGTH)));
        assertFalse(GoogleSecretManagerSecretPipelineWriterImpl.isValidSecretName("a".repeat(GoogleSecretManagerSecretPipelineWriterImpl.MAX_SECRET_NAME_LENGTH + 1)));
        assertFalse(GoogleSecretManagerSecretPipelineWriterImpl.isValidSecretName(""));
        assertFalse(GoogleSecretManagerSecretPipelineWriterImpl.isValidSecretName(null));
    }

    @Test
    void constructor_ChecksTheClientAndProject() {
        assertThrows(NullPointerException.class,
                () -> new GoogleSecretManagerSecretPipelineWriterImpl((com.google.cloud.secretmanager.v1.SecretManagerServiceClient) null,
                        FakeSecretManager.PROJECT_ID, protector, List.of("item")));
        assertThrows(NullPointerException.class, () -> new GoogleSecretManagerSecretPipelineWriterImpl(google.client(), null, protector, List.of("item")));
        assertThrows(IllegalArgumentException.class, () -> new GoogleSecretManagerSecretPipelineWriterImpl(google.client(), "", protector, List.of("item")));
        assertThrows(IllegalArgumentException.class,
                () -> new GoogleSecretManagerSecretPipelineWriterImpl(google.client(), "projects/x", protector, List.of("item")));
    }

    @Test
    void crc32c_IsCastagnolis() {
        assertEquals(0xE3069283L, GoogleSecretManagerSecretPipelineWriterImpl.crc32c(ByteString.copyFromUtf8("123456789")));
    }
}
