package io.github.runsecure.hkdfguard.keywrapping.awskms;

import static io.github.runsecure.hkdfguard.keywrapping.awskms.Futures.await;
import static io.github.runsecure.hkdfguard.keywrapping.awskms.Futures.awaitFailure;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.securefile.KeyFileTrust;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CancellationException;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.core.exception.AbortedException;
import software.amazon.awssdk.core.exception.SdkClientException;
import software.amazon.awssdk.services.kms.model.DataKeySpec;
import software.amazon.awssdk.services.kms.model.DecryptResponse;
import software.amazon.awssdk.services.kms.model.EncryptionAlgorithmSpec;
import software.amazon.awssdk.services.kms.model.GenerateDataKeyWithoutPlaintextResponse;
import software.amazon.awssdk.services.kms.model.InvalidCiphertextException;
import software.amazon.awssdk.services.kms.model.KmsException;
import software.amazon.awssdk.services.kms.model.KmsInternalException;

class AwsKmsKeyWrapperImplTest {
    private static final String KEY_ARN = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";

    private static final Map<String, String> CONTEXT = Map.of("purpose", "hkdfguard.test");

    private static final SecureRandom RANDOM = new SecureRandom();

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

    @Test
    void constructor_RejectsMissingArguments() {
        var kms = new FakeKms();

        assertThrows(NullPointerException.class, () -> new AwsKmsKeyWrapperImpl(null, KEY_ARN));
        assertThrows(NullPointerException.class, () -> new AwsKmsKeyWrapperImpl(kms, null));
        assertThrows(IllegalArgumentException.class, () -> new AwsKmsKeyWrapperImpl(kms, " "));
        assertThrows(IllegalArgumentException.class, () -> new AwsKmsKeyWrapperImpl(kms, KEY_ARN, Map.of("", "x")));
        var nullKey = new HashMap<String, String>();
        nullKey.put(null, "x");
        assertThrows(IllegalArgumentException.class, () -> new AwsKmsKeyWrapperImpl(kms, KEY_ARN, nullKey));
        var nullValue = new HashMap<String, String>();
        nullValue.put("k", null);
        assertThrows(NullPointerException.class, () -> new AwsKmsKeyWrapperImpl(kms, KEY_ARN, nullValue));
    }

    @Test
    void wrapThenUnwrap_RoundTripsTheDek() {
        var wrapper = new AwsKmsKeyWrapperImpl(new FakeKms(), KEY_ARN, CONTEXT);
        var dek = random(32);

        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int wrappedLength = await(wrapper.wrapAsync(dek, wrapped));
        var revealed = new byte[32];
        int revealedLength = await(wrapper.unwrapAsync(Arrays.copyOf(wrapped, wrappedLength), revealed));

        assertEquals(32, revealedLength);
        assertArrayEquals(dek, revealed);
    }

    @Test
    void wrapAsync_SendsTheKeyContextAndAlgorithm_AndZeroesItsCopyOfThePlaintext() {
        var kms = new FakeKms();
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN, CONTEXT);
        var dek = random(32);

        await(wrapper.wrapAsync(dek, new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals(1, kms.encryptRequests.size());
        var request = kms.encryptRequests.getFirst();
        assertEquals(KEY_ARN, request.keyId());
        assertEquals(CONTEXT, request.encryptionContext());
        assertEquals(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT, request.encryptionAlgorithm());
        assertArrayEquals(dek, kms.encryptPlaintexts.getFirst());
        assertTrue(ArrayUtility.isNullOrEmpty(request.plaintext().asByteArrayUnsafe()));
        // The caller's own array is the caller's to zero.
        assertFalse(ArrayUtility.isNullOrEmpty(dek));
    }

    @Test
    void wrapAsync_DoesNotZeroThePlaintextBeforeAnAsynchronousClientHasSentIt() {
        // A real client may serialize the request after encrypt() returns.
        var kms = new FakeKms();
        kms.deferred = true;
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN, CONTEXT);
        var dek = random(32);

        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.wrapAsync(dek, wrapped));
        var revealed = new byte[32];
        await(wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), revealed));

        assertArrayEquals(dek, kms.encryptPlaintexts.getFirst());
        assertArrayEquals(dek, revealed);
        assertTrue(ArrayUtility.isNullOrEmpty(kms.encryptRequests.getFirst().plaintext().asByteArrayUnsafe()));
    }

    @Test
    void withNoContext_SendsNone() {
        var kms = new FakeKms();
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN, Map.of());

        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.generateAndWrapAsync(wrapped));
        await(wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), new byte[32]));

        assertFalse(kms.generateRequests.getFirst().hasEncryptionContext());
        assertFalse(kms.decryptRequests.getFirst().hasEncryptionContext());
    }

    @Test
    void theContextIsCopied_AtConstruction_AndRequestsCanNotChangeIt() {
        var kms = new FakeKms();
        var context = new HashMap<>(CONTEXT);
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN, context);
        context.put("purpose", "changed");

        await(wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));
        // .NET's test changes the first request's dictionary; the SDK's request maps are unmodifiable.
        assertThrows(UnsupportedOperationException.class, () -> kms.generateRequests.getFirst().encryptionContext().put("purpose", "changed by the pipeline"));
        await(wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals("hkdfguard.test", kms.generateRequests.get(0).encryptionContext().get("purpose"));
        assertEquals("hkdfguard.test", kms.generateRequests.get(1).encryptionContext().get("purpose"));
    }

    @Test
    void generateAndWrapAsync_AsksKmsForAWrappedAes256KeyOnly() {
        var kms = new FakeKms();
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN, CONTEXT);

        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.generateAndWrapAsync(wrapped));
        var revealed = new byte[32];
        int revealedLength = await(wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), revealed));

        assertEquals(1, kms.generateRequests.size());
        var request = kms.generateRequests.getFirst();
        assertEquals(KEY_ARN, request.keyId());
        assertEquals(DataKeySpec.AES_256, request.keySpec());
        assertEquals(CONTEXT, request.encryptionContext());
        assertTrue(kms.encryptRequests.isEmpty());
        assertEquals(AwsKmsKeyWrapperImpl.GENERATED_KEY_LENGTH, revealedLength);
        assertFalse(ArrayUtility.isNullOrEmpty(revealed));
    }

    @Test
    void unwrapAsync_PinsTheKey_AndZeroesTheRevealedPlaintext() {
        var kms = new FakeKms();
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN, CONTEXT);
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.wrapAsync(random(32), wrapped));

        await(wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), new byte[32]));

        assertEquals(1, kms.decryptRequests.size());
        var request = kms.decryptRequests.getFirst();
        assertEquals(KEY_ARN, request.keyId());
        assertEquals(EncryptionAlgorithmSpec.SYMMETRIC_DEFAULT, request.encryptionAlgorithm());
        assertArrayEquals(Arrays.copyOf(wrapped, length), request.ciphertextBlob().asByteArray());
        assertTrue(ArrayUtility.isNullOrEmpty(kms.decryptPlaintexts.getFirst().asByteArrayUnsafe()));
    }

    @Test
    void unwrapAsync_UnderAnotherKey_FailsAndZeroesTheResult() {
        var kms = new FakeKms();
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(new AwsKmsKeyWrapperImpl(kms, "alias/other", CONTEXT).wrapAsync(random(32), wrapped));

        var result = filled(32, 0xAA);
        var exception = awaitFailure(CryptographicException.class,
                new AwsKmsKeyWrapperImpl(kms, KEY_ARN, CONTEXT).unwrapAsync(Arrays.copyOf(wrapped, length), result));

        assertInstanceOf(InvalidCiphertextException.class, exception.getCause());
        assertEquals("AWS KMS unwrap failed for key '" + KEY_ARN + "': InvalidCiphertextException (HTTP 400).", exception.getMessage());
        assertTrue(ArrayUtility.isNullOrEmpty(result));
    }

    @Test
    void unwrapAsync_UnderAnotherContext_Fails() {
        var kms = new FakeKms();
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(new AwsKmsKeyWrapperImpl(kms, KEY_ARN, CONTEXT).wrapAsync(random(32), wrapped));
        var other = new AwsKmsKeyWrapperImpl(kms, KEY_ARN, Map.of("purpose", "other"));

        awaitFailure(CryptographicException.class, other.unwrapAsync(Arrays.copyOf(wrapped, length), new byte[32]));
    }

    @Test
    void unwrapAsync_WhenTampered_Fails() {
        var wrapper = new AwsKmsKeyWrapperImpl(new FakeKms(), KEY_ARN, CONTEXT);
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.wrapAsync(random(32), wrapped));
        wrapped[length - 1] ^= 1;

        awaitFailure(CryptographicException.class, wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), new byte[32]));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, WrappedKeyLimits.MAX_BYTES + 1})
    void unwrapAsync_OutOfBounds_FailsWithoutCallingKms(int size) {
        var kms = new FakeKms();
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN);

        awaitFailure(CryptographicException.class, wrapper.unwrapAsync(new byte[size], new byte[32]));

        assertTrue(kms.decryptRequests.isEmpty());
    }

    @Test
    void unwrapAsync_WhenTheKeyDoesNotFit_FailsZeroesTheResultAndTheRevealedPlaintext() {
        var kms = new FakeKms();
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN);
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.wrapAsync(random(32), wrapped));

        var result = filled(16, 0xAA);
        var exception = awaitFailure(IllegalArgumentException.class, wrapper.unwrapAsync(Arrays.copyOf(wrapped, length), result));

        assertTrue(exception.getMessage().contains("result holds 16"));
        assertTrue(ArrayUtility.isNullOrEmpty(result));
        assertTrue(ArrayUtility.isNullOrEmpty(kms.decryptPlaintexts.getFirst().asByteArrayUnsafe()));
    }

    @Test
    void unwrapAsync_WhenKmsReturnsNoPlaintext_Fails() {
        var kms = new FakeKms();
        kms.onDecrypt = request -> DecryptResponse.builder().build();
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN);

        awaitFailure(CryptographicException.class, wrapper.unwrapAsync(new byte[64], new byte[32]));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, AwsKmsKeyWrapperImpl.MAX_PLAINTEXT_LENGTH + 1})
    void wrapAsync_RejectsAPlaintextKmsWouldRefuse(int size) {
        var kms = new FakeKms();
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN);

        var exception = assertThrows(IllegalArgumentException.class, () -> wrapper.wrapAsync(new byte[size], new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(exception.getMessage().contains("got " + size));
        assertTrue(kms.encryptRequests.isEmpty());
    }

    @Test
    void wrapAsync_WhenResultIsTooSmall_Fails() {
        var wrapper = new AwsKmsKeyWrapperImpl(new FakeKms(), KEY_ARN);

        var exception = awaitFailure(IllegalArgumentException.class, wrapper.wrapAsync(new byte[32], new byte[8]));

        assertTrue(exception.getMessage().contains("result holds 8"));
    }

    @Test
    void generateAndWrapAsync_RefusesACiphertextOverTheKeyFileLimit() {
        var kms = new FakeKms();
        kms.onGenerate = request -> GenerateDataKeyWithoutPlaintextResponse.builder()
                .ciphertextBlob(SdkBytes.fromByteArray(new byte[WrappedKeyLimits.MAX_BYTES + 1]))
                .build();
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN);

        awaitFailure(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[2 * WrappedKeyLimits.MAX_BYTES]));
    }

    @Test
    void generateAndWrapAsync_WhenKmsReturnsNoCiphertext_Fails() {
        var kms = new FakeKms();
        kms.onGenerate = request -> GenerateDataKeyWithoutPlaintextResponse.builder().build();
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN);

        awaitFailure(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));
    }

    @Test
    void aServiceRefusal_BecomesACryptographicExceptionNamingTheErrorCode() {
        var kms = new FakeKms();
        kms.onEncrypt = request -> {
            throw FakeKms.<KmsException>serviceError(KmsException.builder(), "AccessDeniedException", 400);
        };
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN);

        var exception = awaitFailure(CryptographicException.class, wrapper.wrapAsync(new byte[32], new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals("AWS KMS wrap failed for key '" + KEY_ARN + "': AccessDeniedException (HTTP 400).", exception.getMessage());
        assertInstanceOf(KmsException.class, exception.getCause());
    }

    @Test
    void aServiceRefusalWithNoErrorCode_IsNamedByItsType() {
        var kms = new FakeKms();
        kms.onDecrypt = request -> {
            throw FakeKms.<KmsInternalException>serviceError(KmsInternalException.builder(), null, 500);
        };
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN);

        var exception = awaitFailure(CryptographicException.class, wrapper.unwrapAsync(new byte[64], new byte[32]));

        assertEquals("AWS KMS unwrap failed for key '" + KEY_ARN + "': KmsInternalException (HTTP 500).", exception.getMessage());
    }

    @Test
    void aClientSideFailure_BecomesACryptographicException() {
        var kms = new FakeKms();
        kms.onGenerate = request -> {
            throw SdkClientException.create("Unable to load credentials from any of the providers in the chain.");
        };
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN);

        var exception = awaitFailure(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertEquals("AWS KMS generate-and-wrap failed for key '" + KEY_ARN
                + "': Unable to load credentials from any of the providers in the chain.", exception.getMessage());
        assertInstanceOf(SdkClientException.class, exception.getCause());
    }

    @Test
    void aClientThatThrowsInsteadOfReturningAFuture_FailsTheFuture() {
        var kms = new FakeKms() {
            @Override
            public java.util.concurrent.CompletableFuture<GenerateDataKeyWithoutPlaintextResponse> generateDataKeyWithoutPlaintext(
                    software.amazon.awssdk.services.kms.model.GenerateDataKeyWithoutPlaintextRequest request) {
                throw SdkClientException.create("Thrown, not returned.");
            }
        };
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN);

        var exception = awaitFailure(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(exception.getMessage().endsWith("Thrown, not returned."));
    }

    @Test
    void cancellation_IsNotWrapped() {
        var kms = new FakeKms();
        kms.onGenerate = request -> {
            throw new CancellationException("Cancelled by the caller.");
        };
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN);

        awaitFailure(CancellationException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));
    }

    @Test
    void anAbortedCall_IsNotWrapped() {
        // The SDK's AbortedException is how it reports an interrupted or aborted call.
        var kms = new FakeKms();
        kms.onDecrypt = request -> {
            throw AbortedException.create("Thread was interrupted.");
        };
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN);
        var result = filled(32, 0xAA);

        awaitFailure(AbortedException.class, wrapper.unwrapAsync(new byte[64], result));

        assertTrue(ArrayUtility.isNullOrEmpty(result));
    }

    @Test
    void cancellingTheFuture_CancelsTheKmsRequest() throws Exception {
        var kms = new FakeKms();
        kms.deferred = true;
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN);

        var future = wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]);
        assertTrue(future.cancel(true));

        var call = kms.futures.getFirst();
        assertTrue(call.isCancelled());
        assertThrows(CancellationException.class, () -> call.get(1, TimeUnit.SECONDS));
    }

    @Test
    void aCryptoProvider_GeneratesAndRevealsItsDekThroughKms() {
        var wrapper = new AwsKmsKeyWrapperImpl(new FakeKms(), KEY_ARN, CONTEXT);
        try (var provider = await(new AesGcmCryptoProviderFactoryImpl().createEphemeralAsync(wrapper, 60))) {
            var expected = "hello, kms".getBytes(StandardCharsets.UTF_8);
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

        var wrapper = new AwsKmsKeyWrapperImpl(new FakeKms(), KEY_ARN, CONTEXT);
        var dir = Files.createTempDirectory("hkdfguard-keys-");
        var path = Files.write(dir.resolve("v1.key"), random(184));
        try {
            awaitFailure(AccessDeniedException.class, wrapper.readKeyFileAsync(path));
        } finally {
            Files.delete(path);
            Files.delete(dir);
        }
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readKeyFile_WithTheWritersAccountTrusted_ReadsTheFile() throws IOException {
        var kms = new FakeKms();
        var wrapper = new AwsKmsKeyWrapperImpl(kms, KEY_ARN, CONTEXT, WindowsTempDirectory.trustCurrentUser());
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
        var wrapper = new AwsKmsKeyWrapperImpl(new FakeKms(), KEY_ARN, CONTEXT, KeyFileTrust.ADMINISTRATORS_ONLY.withWindowsPrincipals("S-1-1-0"));
        try (var dir = new WindowsTempDirectory()) {
            var path = dir.write("v1.key", random(184));

            awaitFailure(IllegalArgumentException.class, wrapper.readKeyFileAsync(path));
        }
    }

    @Test
    void readKeyFile_WithANullTrust_TrustsAdministratorsOnly() throws IOException {
        // The same refusal as the default constructor's: null is AdministratorsOnly, never "anyone".
        var temp = System.getProperty("java.io.tmpdir");
        Assumptions.assumeFalse(System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("mac") && temp.startsWith("/var/folders/"),
                "macOS's per-user temp folder is private to its user.");

        var wrapper = new AwsKmsKeyWrapperImpl(new FakeKms(), KEY_ARN, null, null);
        var dir = Files.createTempDirectory("hkdfguard-keys-");
        var path = Files.write(dir.resolve("v1.key"), random(184));
        try {
            var exception = awaitFailure(AccessDeniedException.class, wrapper.readKeyFileAsync(path));
            assertSame(AccessDeniedException.class, exception.getClass());
        } finally {
            Files.delete(path);
            Files.delete(dir);
        }
    }

    @Test
    void readKeyFile_NullPath_IsRefused() {
        var wrapper = new AwsKmsKeyWrapperImpl(new FakeKms(), KEY_ARN);

        assertThrows(NullPointerException.class, () -> wrapper.readKeyFileAsync((Path) null));
    }
}
