package io.github.runsecure.hkdfguard.keywrapping.googlekms;

import static io.github.runsecure.hkdfguard.keywrapping.googlekms.Futures.assertFailsWith;
import static io.github.runsecure.hkdfguard.keywrapping.googlekms.Futures.await;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.google.api.gax.httpjson.HttpJsonStatusCode;
import com.google.api.gax.rpc.InvalidArgumentException;
import com.google.api.gax.rpc.PermissionDeniedException;
import com.google.api.gax.rpc.StatusCode;
import com.google.cloud.kms.v1.DecryptResponse;
import com.google.cloud.kms.v1.EncryptRequest;
import com.google.protobuf.ByteString;
import com.google.protobuf.Int64Value;
import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.securefile.KeyFileTrust;
import io.github.runsecure.hkdfguard.testsupport.WindowsTempDirectory;
import io.grpc.Status;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class GoogleKmsKeyWrapperImplTest {
    private static final String KEY_NAME = "projects/hkdfguard-test/locations/us-east1/keyRings/hkdfguard/cryptoKeys/wrap";
    private static final String OTHER_KEY_NAME = "projects/hkdfguard-test/locations/us-east1/keyRings/hkdfguard/cryptoKeys/other";
    private static final String CONTEXT = "hkdfguard.test";

    private static final byte[] LABEL = "HkdfGuard-GoogleKms-wrap-v1\0".getBytes(StandardCharsets.US_ASCII);

    private static final SecureRandom RANDOM = new SecureRandom();

    private final FakeCloudKms kms = new FakeCloudKms();

    @AfterEach
    void closeTheFake() throws InterruptedException {
        kms.close();
    }

    private static byte[] random(int length) {
        var bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private static byte[] filled(int length, int value) {
        var bytes = new byte[length];
        Arrays.fill(bytes, (byte) value);
        return bytes;
    }

    private static byte[] concat(byte[] first, byte[] second) {
        var bytes = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, bytes, first.length, second.length);
        return bytes;
    }

    private GoogleKmsKeyWrapperImpl wrapper(String keyName, String context) {
        return new GoogleKmsKeyWrapperImpl(kms.client(), keyName, context);
    }

    @Test
    void constructor_RejectsMissingAndMalformedArguments() {
        var client = kms.client();

        assertThrows(NullPointerException.class, () -> new GoogleKmsKeyWrapperImpl(null, KEY_NAME));
        assertThrows(NullPointerException.class, () -> new GoogleKmsKeyWrapperImpl(client, null));
        for (var keyName : new String[] {
                "",
                "projects/p/locations/l/keyRings/r",
                KEY_NAME + "/cryptoKeyVersions/1",
                KEY_NAME + "/",
                "//cloudkms.googleapis.com/" + KEY_NAME,
                "projects//locations/l/keyRings/r/cryptoKeys/k",
        }) {
            var exception = assertThrows(IllegalArgumentException.class, () -> new GoogleKmsKeyWrapperImpl(client, keyName), keyName);
            assertTrue(exception.getMessage().startsWith("'" + keyName + "' isn't a Cloud KMS key's resource name"), exception.getMessage());
        }
        assertThrows(IllegalArgumentException.class, () ->
                new GoogleKmsKeyWrapperImpl(client, KEY_NAME, "x".repeat(GoogleKmsKeyWrapperImpl.MAX_CONTEXT_LENGTH + 1)));
        var unpaired = assertThrows(IllegalArgumentException.class, () -> new GoogleKmsKeyWrapperImpl(client, KEY_NAME, "a\uD800b"));
        assertEquals("The context isn't well-formed text: it holds an unpaired surrogate.", unpaired.getMessage());
    }

    @Test
    void theLongestContext_FitsCloudKmsAadLimit() {
        var wrapper = wrapper(KEY_NAME, "x".repeat(GoogleKmsKeyWrapperImpl.MAX_CONTEXT_LENGTH));

        await(wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(kms.encryptRequests.getFirst().getAdditionalAuthenticatedData().size() <= 64 * 1024);
    }

    @Test
    void wrapThenUnwrap_RoundTripsTheDek() {
        var wrapper = wrapper(KEY_NAME, CONTEXT);
        var dek = random(32);

        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int wrappedLength = await(wrapper.wrapAsync(dek, wrapped));
        var revealed = new byte[32];
        int revealedLength = await(wrapper.unwrapAsync(Arrays.copyOf(wrapped, wrappedLength), revealed));

        assertEquals(32, revealedLength);
        assertArrayEquals(dek, revealed);
    }

    @Test
    void wrapAsync_SendsTheKeyLabelledContextAndChecksums_AndZeroesItsCopyOfThePlaintext() {
        var wrapper = wrapper(KEY_NAME, CONTEXT);
        var dek = random(32);

        await(wrapper.wrapAsync(dek, new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals(1, kms.encryptRequests.size());
        var request = kms.encryptRequests.getFirst();
        assertEquals(KEY_NAME, request.getName());
        assertArrayEquals(concat(LABEL, CONTEXT.getBytes(StandardCharsets.UTF_8)), request.getAdditionalAuthenticatedData().toByteArray());
        assertEquals(GoogleKmsKeyWrapperImpl.crc32c(dek), request.getPlaintextCrc32C().getValue());
        assertEquals(GoogleKmsKeyWrapperImpl.crc32c(request.getAdditionalAuthenticatedData()), request.getAdditionalAuthenticatedDataCrc32C().getValue());
        assertArrayEquals(dek, kms.encryptPlaintexts.getFirst());
        assertTrue(ArrayUtility.isNullOrEmpty(request.getPlaintext().toByteArray()));
        // The caller's own array is the caller's to zero.
        assertFalse(ArrayUtility.isNullOrEmpty(dek));
    }

    @Test
    void wrapAsync_RetriedByTheClient_SendsThePlaintextAgain() {
        // The client retries an UNAVAILABLE Encrypt; the plaintext is zeroed only once it is done.
        var attempts = new AtomicInteger();
        kms.onEncrypt = request -> {
            if (attempts.getAndIncrement() == 0)
                throw FakeCloudKms.error(Status.Code.UNAVAILABLE, "Try again.");
            return kms.encryptNormally(request).build();
        };
        var wrapper = wrapper(KEY_NAME, CONTEXT);
        var dek = random(32);

        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.wrapAsync(dek, wrapped));
        kms.onEncrypt = null;
        var revealed = new byte[32];
        await(wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), revealed));

        assertEquals(2, kms.encryptRequests.size());
        assertArrayEquals(dek, kms.encryptPlaintexts.get(0));
        assertArrayEquals(dek, kms.encryptPlaintexts.get(1));
        assertArrayEquals(dek, revealed);
        assertTrue(ArrayUtility.isNullOrEmpty(kms.encryptRequests.get(1).getPlaintext().toByteArray()));
    }

    @Test
    void unwrapAsync_PinsTheKeyAndSendsChecksums_AndZeroesTheRevealedBytes() {
        var wrapper = wrapper(KEY_NAME, CONTEXT);
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.wrapAsync(random(32), wrapped));

        await(wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), new byte[32]));

        assertEquals(1, kms.decryptRequests.size());
        var request = kms.decryptRequests.getFirst();
        assertEquals(KEY_NAME, request.getName());
        assertArrayEquals(Arrays.copyOf(wrapped, length), request.getCiphertext().toByteArray());
        assertEquals(GoogleKmsKeyWrapperImpl.crc32c(Arrays.copyOf(wrapped, length)), request.getCiphertextCrc32C().getValue());
        assertEquals(kms.encryptRequests.getFirst().getAdditionalAuthenticatedData(), request.getAdditionalAuthenticatedData());
        assertEquals(kms.encryptRequests.getFirst().getAdditionalAuthenticatedDataCrc32C(), request.getAdditionalAuthenticatedDataCrc32C());
        assertEquals(32, kms.decryptPlaintexts.getFirst().size());
        assertTrue(ArrayUtility.isNullOrEmpty(kms.decryptPlaintexts.getFirst().toByteArray()));
    }

    @Test
    void aNullAndAnEmptyContext_BindTheLabelOnly() {
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(new GoogleKmsKeyWrapperImpl(kms.client(), KEY_NAME).generateAndWrapAsync(wrapped));

        await(wrapper(KEY_NAME, "").unwrapAsync(Arrays.copyOf(wrapped, length), new byte[32]));

        assertArrayEquals(LABEL, kms.encryptRequests.getFirst().getAdditionalAuthenticatedData().toByteArray());
    }

    @Test
    void generateAndWrapAsync_WrapsAFresh32ByteDek_AndZeroesIt() {
        var wrapper = wrapper(KEY_NAME, CONTEXT);

        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.generateAndWrapAsync(wrapped));
        var revealed = new byte[32];
        int revealedLength = await(wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), revealed));

        assertEquals(GoogleKmsKeyWrapperImpl.GENERATED_KEY_LENGTH, revealedLength);
        assertArrayEquals(revealed, kms.encryptPlaintexts.getFirst());
        assertFalse(ArrayUtility.isNullOrEmpty(revealed));
        assertTrue(ArrayUtility.isNullOrEmpty(kms.encryptRequests.getFirst().getPlaintext().toByteArray()));
    }

    @Test
    void keyFilesFromEveryVersion_StillUnwrapAfterTheKeyIsRotated() {
        var wrapper = wrapper(KEY_NAME, CONTEXT);
        var before = new byte[WrappedKeyLimits.MAX_BYTES];
        int beforeLength = await(wrapper.generateAndWrapAsync(before));

        kms.rotate(KEY_NAME);
        var after = new byte[WrappedKeyLimits.MAX_BYTES];
        int afterLength = await(wrapper.generateAndWrapAsync(after));

        assertEquals(32, await(wrapper.unwrapAsync(Arrays.copyOf(before, beforeLength), new byte[32])));
        assertEquals(32, await(wrapper.unwrapAsync(Arrays.copyOf(after, afterLength), new byte[32])));
    }

    @Test
    void unwrapAsync_UnderAnotherKey_FailsAndZeroesTheResult() {
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper(OTHER_KEY_NAME, CONTEXT).wrapAsync(random(32), wrapped));

        var result = filled(32, 0xAA);
        var exception = assertFailsWith(CryptographicException.class,
                wrapper(KEY_NAME, CONTEXT).unwrapAsync(Arrays.copyOf(wrapped, length), result));

        assertInstanceOf(InvalidArgumentException.class, exception.getCause());
        assertEquals("Cloud KMS unwrap failed for key '" + KEY_NAME + "': INVALID_ARGUMENT: Decryption failed: the ciphertext is invalid.",
                exception.getMessage());
        assertTrue(ArrayUtility.isNullOrEmpty(result));
    }

    @Test
    void unwrapAsync_UnderAnotherContext_Fails() {
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper(KEY_NAME, CONTEXT).generateAndWrapAsync(wrapped));

        assertFailsWith(CryptographicException.class, wrapper(KEY_NAME, "other").unwrapAsync(Arrays.copyOf(wrapped, length), new byte[32]));
    }

    @Test
    void unwrapAsync_ACiphertextMadeWithoutTheLabel_IsRefused() {
        // What any other use of the same key produces: the right key, but not an HkdfGuard DEK.
        var foreign = kms.client().encrypt(EncryptRequest.newBuilder()
                .setName(KEY_NAME)
                .setPlaintext(ByteString.copyFrom(random(32)))
                .setAdditionalAuthenticatedData(ByteString.copyFromUtf8(CONTEXT))
                .build());

        assertFailsWith(CryptographicException.class, wrapper(KEY_NAME, CONTEXT).unwrapAsync(foreign.getCiphertext().toByteArray(), new byte[32]));
    }

    @Test
    void unwrapAsync_WhenTampered_Fails() {
        var wrapper = wrapper(KEY_NAME, CONTEXT);
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.generateAndWrapAsync(wrapped));
        wrapped[length - 1] ^= 1;

        assertFailsWith(CryptographicException.class, wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), new byte[32]));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, WrappedKeyLimits.MAX_BYTES + 1})
    void unwrapAsync_OutOfBounds_FailsWithoutCallingKms(int size) {
        var wrapper = wrapper(KEY_NAME, null);

        assertFailsWith(CryptographicException.class, wrapper.unwrapAsync(new byte[size], new byte[32]));

        assertTrue(kms.decryptRequests.isEmpty());
    }

    @Test
    void unwrapAsync_WhenTheKeyDoesNotFit_FailsZeroesTheResultAndScrubsThePlaintext() {
        var wrapper = wrapper(KEY_NAME, null);
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.generateAndWrapAsync(wrapped));

        var result = filled(16, 0xAA);
        var exception = assertFailsWith(IllegalArgumentException.class, wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), result));

        assertEquals("The revealed key is 32 bytes; result holds 16.", exception.getMessage());
        assertTrue(ArrayUtility.isNullOrEmpty(result));
        assertTrue(ArrayUtility.isNullOrEmpty(kms.decryptPlaintexts.getFirst().toByteArray()));
    }

    @Test
    void unwrapAsync_WhenKmsReturnsNoPlaintext_Fails() {
        kms.onDecrypt = request -> DecryptResponse.newBuilder().setPlaintextCrc32C(Int64Value.of(0)).build();

        var exception = assertFailsWith(CryptographicException.class, wrapper(KEY_NAME, null).unwrapAsync(new byte[64], new byte[32]));

        assertEquals("Cloud KMS unwrap for key '" + KEY_NAME + "' returned no plaintext.", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void unwrapAsync_WhenThePlaintextDoesNotMatchItsChecksum_FailsAndScrubsIt(boolean missing) {
        kms.onDecrypt = request -> {
            var plaintext = random(32);
            var response = DecryptResponse.newBuilder().setPlaintext(ByteString.copyFrom(plaintext));
            if (!missing)
                response.setPlaintextCrc32C(Int64Value.of(GoogleKmsKeyWrapperImpl.crc32c(plaintext) ^ 1));
            return response.build();
        };
        var result = filled(32, 0xAA);

        var exception = assertFailsWith(CryptographicException.class, wrapper(KEY_NAME, null).unwrapAsync(new byte[64], result));

        assertTrue(exception.getMessage().contains("corrupted in transit"), exception.getMessage());
        assertTrue(ArrayUtility.isNullOrEmpty(result));
        assertTrue(ArrayUtility.isNullOrEmpty(kms.decryptPlaintexts.getFirst().toByteArray()));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, GoogleKmsKeyWrapperImpl.MAX_PLAINTEXT_LENGTH + 1})
    void wrapAsync_RejectsAPlaintextKmsWouldRefuse(int size) {
        var wrapper = wrapper(KEY_NAME, null);

        var exception = assertThrows(IllegalArgumentException.class, () -> wrapper.wrapAsync(new byte[size], new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(exception.getMessage().contains("got " + size));
        assertTrue(kms.encryptRequests.isEmpty());
    }

    @Test
    void wrapAsync_WhenResultIsTooSmall_Fails() {
        var exception = assertFailsWith(IllegalArgumentException.class, wrapper(KEY_NAME, null).wrapAsync(new byte[32], new byte[8]));

        assertTrue(exception.getMessage().endsWith("result holds 8."), exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            OTHER_KEY_NAME + "/cryptoKeyVersions/1",
            KEY_NAME,
            KEY_NAME + "/cryptoKeyVersions/",
            KEY_NAME + "/cryptoKeyVersions/1/x",
            KEY_NAME + "x/cryptoKeyVersions/1",
            "",
    })
    void wrapAsync_RefusesAResponseFromAnyVersionButThisKeys(String reportedName) {
        kms.onEncrypt = request -> kms.encryptNormally(request).setName(reportedName).build();

        var exception = assertFailsWith(CryptographicException.class, wrapper(KEY_NAME, null).generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals("Cloud KMS wrap for key '" + KEY_NAME + "' reported key version '" + reportedName + "' instead.", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void wrapAsync_RefusesAResponseThatDidNotVerifyTheRequestChecksums(boolean plaintextVerified) {
        kms.onEncrypt = request -> kms.encryptNormally(request)
                .setVerifiedPlaintextCrc32C(plaintextVerified)
                .setVerifiedAdditionalAuthenticatedDataCrc32C(!plaintextVerified)
                .build();

        var exception = assertFailsWith(CryptographicException.class, wrapper(KEY_NAME, null).generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(exception.getMessage().contains("didn't verify the request's checksums"), exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void wrapAsync_RefusesACiphertextThatDoesNotMatchItsChecksum(boolean missing) {
        kms.onEncrypt = request -> {
            var response = kms.encryptNormally(request);
            return missing
                    ? response.clearCiphertextCrc32C().build()
                    : response.setCiphertextCrc32C(Int64Value.of(response.getCiphertextCrc32C().getValue() ^ 1)).build();
        };

        var exception = assertFailsWith(CryptographicException.class, wrapper(KEY_NAME, null).generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(exception.getMessage().contains("corrupted in transit"), exception.getMessage());
    }

    @Test
    void wrapAsync_WhenKmsReturnsNoCiphertext_Fails() {
        kms.onEncrypt = request -> kms.encryptNormally(request).setCiphertext(ByteString.EMPTY).build();

        var exception = assertFailsWith(CryptographicException.class, wrapper(KEY_NAME, null).generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals("Cloud KMS wrap for key '" + KEY_NAME + "' returned no ciphertext.", exception.getMessage());
    }

    @Test
    void wrapAsync_RefusesACiphertextOverTheKeyFileLimit() {
        var ciphertext = new byte[WrappedKeyLimits.MAX_BYTES + 1];
        kms.onEncrypt = request -> kms.encryptNormally(request)
                .setCiphertext(ByteString.copyFrom(ciphertext))
                .setCiphertextCrc32C(Int64Value.of(GoogleKmsKeyWrapperImpl.crc32c(ciphertext)))
                .build();

        var exception = assertFailsWith(CryptographicException.class,
                wrapper(KEY_NAME, null).generateAndWrapAsync(new byte[2 * WrappedKeyLimits.MAX_BYTES]));

        assertTrue(exception.getMessage().endsWith("a wrapped DEK is at most " + WrappedKeyLimits.MAX_BYTES + "."), exception.getMessage());
    }

    @Test
    void aServiceRefusal_BecomesACryptographicExceptionNamingTheStatus() {
        kms.onEncrypt = request -> {
            throw FakeCloudKms.error(Status.Code.PERMISSION_DENIED, "Permission 'cloudkms.cryptoKeyVersions.useToEncrypt' denied.");
        };

        var exception = assertFailsWith(CryptographicException.class, wrapper(KEY_NAME, null).wrapAsync(new byte[32], new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals("Cloud KMS wrap failed for key '" + KEY_NAME
                + "': PERMISSION_DENIED: Permission 'cloudkms.cryptoKeyVersions.useToEncrypt' denied.", exception.getMessage());
        assertInstanceOf(PermissionDeniedException.class, exception.getCause());
    }

    @Test
    void anApiExceptionWithoutAGrpcStatus_IsNamedByItsMessage() {
        // The client's other transport (HTTP/JSON) raises ApiException over no gRPC status.
        var error = new PermissionDeniedException("Permission denied over HTTP/JSON.", null,
                HttpJsonStatusCode.of(StatusCode.Code.PERMISSION_DENIED), false);
        var wrapper = new GoogleKmsKeyWrapperImpl(FailingClient.failingWith(error), KEY_NAME);

        var exception = assertFailsWith(CryptographicException.class, wrapper.unwrapAsync(new byte[64], new byte[32]));

        assertEquals("Cloud KMS unwrap failed for key '" + KEY_NAME + "': PERMISSION_DENIED: Permission denied over HTTP/JSON.", exception.getMessage());
        assertSame(error, exception.getCause());
    }

    @Test
    void aClientSideFailure_BecomesACryptographicException() {
        var error = new IllegalStateException("The Application Default Credentials are not available.");
        var result = filled(32, 0xAA);
        var wrapper = new GoogleKmsKeyWrapperImpl(FailingClient.failingWith(error), KEY_NAME);

        var exception = assertFailsWith(CryptographicException.class, wrapper.unwrapAsync(new byte[64], result));

        assertEquals("Cloud KMS unwrap failed for key '" + KEY_NAME + "': The Application Default Credentials are not available.", exception.getMessage());
        assertSame(error, exception.getCause());
        assertTrue(ArrayUtility.isNullOrEmpty(result));
    }

    @Test
    void aCryptographicExceptionFromTheClient_IsNotWrappedAgain() {
        var thrown = new CryptographicException("from the client");
        var wrapper = new GoogleKmsKeyWrapperImpl(FailingClient.failingWith(thrown), KEY_NAME);

        assertSame(thrown, assertFailsWith(CryptographicException.class, wrapper.unwrapAsync(new byte[64], new byte[32])));
    }

    @Test
    void aClientThatThrowsInsteadOfReturningAFuture_FailsTheFuture() {
        var wrapper = new GoogleKmsKeyWrapperImpl(FailingClient.throwing(new IllegalStateException("Thrown, not returned.")), KEY_NAME);

        var exception = assertFailsWith(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(exception.getMessage().endsWith("Thrown, not returned."), exception.getMessage());
    }

    @Test
    void aClientThatReturnsNoFuture_FailsTheFuture() {
        var wrapper = new GoogleKmsKeyWrapperImpl(FailingClient.returningNoFuture(), KEY_NAME);

        var exception = assertFailsWith(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(exception.getMessage().endsWith("The Cloud KMS client returned no future."), exception.getMessage());
    }

    @Test
    void aCancellationFromTheClient_IsNotWrapped() {
        var wrapper = new GoogleKmsKeyWrapperImpl(FailingClient.failingWith(new CancellationException("Cancelled by the client.")), KEY_NAME);

        assertFailsWith(CancellationException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));
    }

    @Test
    void aCancelledStatusTheCallerDidNotAskFor_IsAFailure() {
        kms.onEncrypt = request -> {
            throw FakeCloudKms.error(Status.Code.CANCELLED, "Canceled by the server.");
        };

        var exception = assertFailsWith(CryptographicException.class, wrapper(KEY_NAME, null).generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals("Cloud KMS wrap failed for key '" + KEY_NAME + "': CANCELLED: Canceled by the server.", exception.getMessage());
    }

    @Test
    void cancellingTheFuture_CancelsTheKmsRequest() throws InterruptedException {
        kms.hang = true;
        var wrapper = wrapper(KEY_NAME, CONTEXT);
        var result = filled(32, 0xAA);

        var future = wrapper.unwrapAsync(new byte[64], result);
        assertFalse(future.isDone());
        assertTrue(future.cancel(true));

        assertTrue(kms.cancelled.await(5, TimeUnit.SECONDS), "Cloud KMS never saw the call cancelled.");
        assertThrows(CancellationException.class, () -> future.get(1, TimeUnit.SECONDS));
    }

    @Test
    void crc32c_MatchesTheCastagnoliCheckValue() {
        assertEquals(0xE3069283L, GoogleKmsKeyWrapperImpl.crc32c("123456789".getBytes(StandardCharsets.US_ASCII)));
        assertEquals(0xE3069283L, GoogleKmsKeyWrapperImpl.crc32c(ByteString.copyFromUtf8("123456789")));
        assertEquals(0L, GoogleKmsKeyWrapperImpl.crc32c(new byte[0]));
    }

    @Test
    void scrub_ZeroesTheBytesAByteStringHolds() {
        var bytes = ByteString.copyFrom(new byte[] {1, 2, 3});
        GoogleKmsKeyWrapperImpl.scrub(bytes);
        assertArrayEquals(new byte[3], bytes.toByteArray());

        // A substring shares its parent's array: only its own bytes are zeroed.
        var parent = ByteString.copyFrom(new byte[] {1, 2, 3, 4});
        GoogleKmsKeyWrapperImpl.scrub(parent.substring(1, 3));
        assertArrayEquals(new byte[] {1, 0, 0, 4}, parent.toByteArray());

        // A concatenation holds its parts' arrays.
        var left = ByteString.copyFrom(filled(200, 7));
        var right = ByteString.copyFrom(filled(200, 9));
        GoogleKmsKeyWrapperImpl.scrub(left.concat(right));
        assertTrue(ArrayUtility.isNullOrEmpty(left.toByteArray()));
        assertTrue(ArrayUtility.isNullOrEmpty(right.toByteArray()));

        GoogleKmsKeyWrapperImpl.scrub(ByteString.EMPTY);
    }

    @Test
    void aCryptoProvider_GeneratesAndRevealsItsDekThroughKms() {
        var wrapper = wrapper(KEY_NAME, CONTEXT);
        try (var provider = await(new AesGcmCryptoProviderFactoryImpl().createEphemeralAsync(wrapper, 60))) {
            var expected = "hello, cloud kms".getBytes(StandardCharsets.UTF_8);
            // Encrypt zeroes the plaintext it is given, so it gets a copy.
            var plaintext = expected.clone();
            var encrypted = new byte[provider.getEncryptedAllocationLength(plaintext.length)];
            int encryptedLength = provider.encrypt(plaintext, encrypted);
            var decrypted = new byte[provider.getDecryptedAllocationLength(encryptedLength)];
            int decryptedLength = provider.decrypt(Arrays.copyOf(encrypted, encryptedLength), decrypted);

            assertArrayEquals(expected, Arrays.copyOf(decrypted, decryptedLength));
        }
    }

    @Test
    void readKeyFile_ByDefault_RefusesAFileTheCurrentUserCouldHaveReplaced() throws IOException {
        // The user's temp folder (Windows) or the shared /tmp (Linux): neither is somewhere only
        // administrators can write.
        var temp = System.getProperty("java.io.tmpdir");
        Assumptions.assumeFalse(System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("mac") && temp.startsWith("/var/folders/"),
                "macOS's per-user temp folder is private to its user; TrustedKeyFileTest covers macOS.");

        var wrapper = wrapper(KEY_NAME, CONTEXT);
        var dir = Files.createTempDirectory("hkdfguard-keys-");
        var path = Files.write(dir.resolve("v1.key"), random(89));
        try {
            assertFailsWith(AccessDeniedException.class, wrapper.readKeyFileAsync(path));
        } finally {
            Files.delete(path);
            Files.delete(dir);
        }
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readKeyFile_WithTheWritersAccountTrusted_ReadsTheFile() throws IOException {
        var wrapper = new GoogleKmsKeyWrapperImpl(kms.client(), KEY_NAME, CONTEXT, trustCurrentWindowsUser());
        try (var dir = new WindowsTempDirectory()) {
            var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
            int length = await(wrapper.generateAndWrapAsync(wrapped));
            var path = dir.write("v1.key", Arrays.copyOf(wrapped, length));

            var read = await(wrapper.readKeyFileAsync(path));
            assertArrayEquals(Arrays.copyOf(wrapped, length), read);
            assertEquals(32, await(wrapper.unwrapAsync(read, new byte[32])));
        }
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readKeyFile_TrustingEveryone_IsRefused() throws IOException {
        var wrapper = new GoogleKmsKeyWrapperImpl(kms.client(), KEY_NAME, CONTEXT, KeyFileTrust.ADMINISTRATORS_ONLY.withWindowsPrincipals("S-1-1-0"));
        try (var dir = new WindowsTempDirectory()) {
            var path = dir.write("v1.key", random(89));

            assertFailsWith(IllegalArgumentException.class, wrapper.readKeyFileAsync(path));
        }
    }

    @Test
    void readKeyFile_WithANullTrust_TrustsAdministratorsOnly() throws IOException {
        // The same refusal as the shorter constructors': null is AdministratorsOnly, never "anyone".
        var temp = System.getProperty("java.io.tmpdir");
        Assumptions.assumeFalse(System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("mac") && temp.startsWith("/var/folders/"),
                "macOS's per-user temp folder is private to its user.");

        var wrapper = new GoogleKmsKeyWrapperImpl(kms.client(), KEY_NAME, null, null);
        var dir = Files.createTempDirectory("hkdfguard-keys-");
        var path = Files.write(dir.resolve("v1.key"), random(89));
        try {
            var exception = assertFailsWith(AccessDeniedException.class, wrapper.readKeyFileAsync(path));
            assertSame(AccessDeniedException.class, exception.getClass());
        } finally {
            Files.delete(path);
            Files.delete(dir);
        }
    }

    @Test
    void readKeyFile_NullPath_IsRefused() {
        var wrapper = wrapper(KEY_NAME, null);

        assertThrows(NullPointerException.class, () -> wrapper.readKeyFileAsync((Path) null));
    }

    /** Trusts the account running the tests, which owns, and may modify, its own temp folder. */
    private static KeyFileTrust trustCurrentWindowsUser() {
        return KeyFileTrust.ADMINISTRATORS_ONLY.withWindowsPrincipals(WindowsTempDirectory.currentUserSid());
    }
}
