package io.github.runsecure.hkdfguard.keywrapping.azurekeyvault;

import static io.github.runsecure.hkdfguard.keywrapping.azurekeyvault.Futures.assertFailsWith;
import static io.github.runsecure.hkdfguard.keywrapping.azurekeyvault.Futures.await;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.azure.core.credential.TokenCredential;
import com.azure.core.exception.HttpResponseException;
import com.azure.security.keyvault.keys.cryptography.models.KeyWrapAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.SignResult;
import com.azure.security.keyvault.keys.cryptography.models.SignatureAlgorithm;
import com.azure.security.keyvault.keys.cryptography.models.UnwrapResult;
import com.azure.security.keyvault.keys.cryptography.models.VerifyResult;
import com.azure.security.keyvault.keys.cryptography.models.WrapResult;
import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import io.github.runsecure.hkdfguard.cryptoprovider.aesgcm256.AesGcmCryptoProviderFactoryImpl;
import io.github.runsecure.hkdfguard.securefile.KeyFileTrust;
import io.github.runsecure.hkdfguard.testsupport.WindowsTempDirectory;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import reactor.core.publisher.Mono;

class AzureKeyVaultKeyWrapperImplTest {
    private static final String CONTEXT = "com.example.myapp";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final FakeKeyVault vault = new FakeKeyVault();

    private AzureKeyVaultKeyWrapperImpl wrapper() {
        return wrapper(CONTEXT, FakeKeyVault.WRAPPING_KEY_ID, FakeKeyVault.SIGNING_KEY_ID);
    }

    private AzureKeyVaultKeyWrapperImpl wrapper(String context) {
        return wrapper(context, FakeKeyVault.WRAPPING_KEY_ID, FakeKeyVault.SIGNING_KEY_ID);
    }

    private AzureKeyVaultKeyWrapperImpl wrapper(String context, String wrappingKeyId, String signingKeyId) {
        return new AzureKeyVaultKeyWrapperImpl(wrappingKeyId, signingKeyId, vault::client, context, null);
    }

    private static byte[] wrap(AzureKeyVaultKeyWrapperImpl wrapper, byte[] dek) {
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.wrapAsync(dek, wrapped));
        return Arrays.copyOf(wrapped, length);
    }

    private static byte[] unwrap(AzureKeyVaultKeyWrapperImpl wrapper, byte[] wrapped) {
        var revealed = new byte[64];
        int length = await(wrapper.unwrapAsync(wrapped, revealed));
        return Arrays.copyOf(revealed, length);
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

    @Test
    void constructor_RejectsMissingOrInvalidArguments() {
        Function<String, KeyVaultKeyClient> clients = vault::client;
        assertThrows(NullPointerException.class, () -> new AzureKeyVaultKeyWrapperImpl(null, FakeKeyVault.SIGNING_KEY_ID, clients, null, null));
        assertThrows(NullPointerException.class, () -> new AzureKeyVaultKeyWrapperImpl(FakeKeyVault.WRAPPING_KEY_ID, null, clients, null, null));
        assertThrows(NullPointerException.class, () -> new AzureKeyVaultKeyWrapperImpl(FakeKeyVault.WRAPPING_KEY_ID, FakeKeyVault.SIGNING_KEY_ID, (TokenCredential) null));
        assertThrows(IllegalArgumentException.class, () -> wrapper(CONTEXT, "https://example.com/not/a/key/id/at/all", FakeKeyVault.SIGNING_KEY_ID));
        assertThrows(IllegalArgumentException.class, () -> wrapper(new String(new char[65_536]).replace('\0', 'x')));
        // .NET encodes an unpaired surrogate as U+FFFD, Java as '?': refused, so neither signs a context the other can't.
        assertThrows(IllegalArgumentException.class, () -> wrapper("app\uD800"));
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "https://hkdfguard-test.vault.azure.net/secrets/hkdfguard-wrap",      // a secret's identifier
        "https://hkdfguard-test.vault.azure.net/keys",                        // no name
        "https://hkdfguard-test.vault.azure.net/keys/hkdfguard-wrap/v/extra", // too long
        "http://hkdfguard-test.vault.azure.net/keys/hkdfguard-wrap",          // not https
        "https://hkdfguard-test.vault.azure.net/keys/hkdfguard-wrap?x=1",     // a query
        "https://user@hkdfguard-test.vault.azure.net/keys/hkdfguard-wrap",    // user information
        "https://hkdfguard-test.vault.azure.net/keys/hkdfguard_wrap",         // not a Key Vault name
        "/keys/hkdfguard-wrap",                                               // not absolute
        "not a uri"
    })
    void constructor_RefusesWhatIsNotAKeyVaultKeyIdentifier(String keyId) {
        var exception = assertThrows(IllegalArgumentException.class, () -> wrapper(CONTEXT, keyId, FakeKeyVault.SIGNING_KEY_ID));

        assertTrue(exception.getMessage().contains("isn't a Key Vault key identifier"), exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "https://hkdfguard-test.vault.azure.net/keys/hkdfguard-wrap",
        "https://HKDFGUARD-TEST.vault.azure.net/keys/HKDFGUARD-WRAP/0123456789abcdef0123456789abcdef",
        "https://hkdfguard-test.vault.azure.net/keys/hkdfguard-wrap/"
    })
    void constructor_RefusesTheSameKeyForWrappingAndSigning(String signingKeyId) {
        var exception = assertThrows(IllegalArgumentException.class, () -> wrapper(CONTEXT, FakeKeyVault.WRAPPING_KEY_ID, signingKeyId));

        assertTrue(exception.getMessage().contains("separate EC P-256 key"));
    }

    @Test
    void constructor_AllowsKeysWithTheSameNameInDifferentVaults() {
        wrapper(CONTEXT, FakeKeyVault.WRAPPING_KEY_ID, "https://other-vault.vault.azure.net/keys/" + FakeKeyVault.WRAPPING_KEY_NAME);
        // The port is part of the vault.
        wrapper(CONTEXT, FakeKeyVault.WRAPPING_KEY_ID, "https://hkdfguard-test.vault.azure.net:8443/keys/" + FakeKeyVault.WRAPPING_KEY_NAME);
    }

    @Test
    void wrapThenUnwrap_RoundTripsTheDek() {
        var wrapper = wrapper();
        var dek = random(32);

        var wrapped = wrap(wrapper, dek);

        assertArrayEquals(dek, unwrap(wrapper, wrapped));
        assertEquals(256 + WrappedDekEnvelope.OVERHEAD, wrapped.length); // RSA-2048
        assertArrayEquals(dek, vault.lastWrapped);
    }

    @Test
    void wrap_ZeroesItsCopyOfThePlaintext_ButNotTheCallers() {
        var dek = random(32);

        wrap(wrapper(), dek);

        assertTrue(ArrayUtility.isNullOrEmpty(vault.lastWrappedArray));
        assertFalse(ArrayUtility.isNullOrEmpty(dek));
    }

    @Test
    void wrap_DoesNotZeroThePlaintextBeforeAnAsynchronousClientHasSentIt() {
        // A real client may serialize the request after wrapKey() returns.
        vault.deferred = true;
        var wrapper = wrapper();
        var dek = random(32);

        var wrapped = wrap(wrapper, dek);

        assertArrayEquals(dek, vault.lastWrapped);
        assertArrayEquals(dek, unwrap(wrapper, wrapped));
    }

    @Test
    void wrap_WrapsUnderTheCurrentVersions_AndRecordsThem() {
        var parts = WrappedDekEnvelope.parse(wrap(wrapper(), random(32)));

        assertEquals(vault.currentVersion(FakeKeyVault.WRAPPING_KEY_NAME), parts.wrappingKeyVersion());
        assertEquals(vault.currentVersion(FakeKeyVault.SIGNING_KEY_NAME), parts.signingKeyVersion());
        assertEquals(List.of("wrap " + FakeKeyVault.WRAPPING_KEY_ID, "sign " + FakeKeyVault.SIGNING_KEY_ID), vault.calls);
    }

    @Test
    void unwrap_VerifiesTheSignatureFirst_ThenUnwrapsUnderTheRecordedVersions() {
        var wrapper = wrapper();
        var wrapped = wrap(wrapper, random(32));
        var wrapVersion = vault.currentVersion(FakeKeyVault.WRAPPING_KEY_NAME);
        var signVersion = vault.currentVersion(FakeKeyVault.SIGNING_KEY_NAME);
        vault.calls.clear();

        unwrap(wrapper, wrapped);

        assertEquals(List.of("verify " + FakeKeyVault.SIGNING_KEY_ID + "/" + signVersion, "unwrap " + FakeKeyVault.WRAPPING_KEY_ID + "/" + wrapVersion),
                vault.calls);
    }

    @Test
    void unwrap_AfterBothKeysRotate_StillRevealsOlderKeyFiles() {
        var wrapper = wrapper();
        var dek = random(32);
        var older = wrap(wrapper, dek);

        vault.addVersion(FakeKeyVault.WRAPPING_KEY_NAME, FakeKeyVault.rsa(2048));
        vault.addVersion(FakeKeyVault.SIGNING_KEY_NAME, FakeKeyVault.p256());
        var newer = WrappedDekEnvelope.parse(wrap(wrapper, dek));

        assertArrayEquals(dek, unwrap(wrapper, older));
        assertEquals(vault.currentVersion(FakeKeyVault.WRAPPING_KEY_NAME), newer.wrappingKeyVersion());
    }

    @Test
    void generateAndWrap_ProducesA32ByteDekThatReveals() {
        var wrapper = wrapper();
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];

        int length = await(wrapper.generateAndWrapAsync(wrapped));
        var revealed = unwrap(wrapper, Arrays.copyOf(wrapped, length));

        assertEquals(AzureKeyVaultKeyWrapperImpl.GENERATED_KEY_LENGTH, revealed.length);
        assertFalse(ArrayUtility.isNullOrEmpty(revealed));
        assertTrue(ArrayUtility.isNullOrEmpty(vault.lastWrappedArray));
    }

    @Test
    void unwrap_AWrappedDekForgedFromThePublicKey_IsRefused_WithoutUnwrapping() throws Exception {
        // What anyone holding the public wrapping key can make: a real RSA-OAEP ciphertext of a DEK
        // they chose, signed with an EC key of their own.
        var chosen = random(32);
        var cipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        cipher.init(Cipher.ENCRYPT_MODE, vault.publicWrappingKey(),
                new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
        var unsigned = WrappedDekEnvelope.buildUnsigned(vault.currentVersion(FakeKeyVault.WRAPPING_KEY_NAME), cipher.doFinal(chosen));
        var signer = Signature.getInstance("SHA256withECDSAinP1363Format");
        signer.initSign(FakeKeyVault.p256().getPrivate());
        signer.update(WrappedDekEnvelope.signedData(unsigned, unsigned.length, WrappedDekEnvelope.encodeContext(CONTEXT)));
        var forged = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = WrappedDekEnvelope.write(unsigned, vault.currentVersion(FakeKeyVault.SIGNING_KEY_NAME), signer.sign(), forged);

        var revealed = filled(32, 0xAA);
        var exception = assertFailsWith(CryptographicException.class, wrapper().unwrapAsync(Arrays.copyOf(forged, length), revealed));

        assertTrue(exception.getMessage().contains("signature doesn't verify"));
        assertTrue(vault.calls.stream().noneMatch(call -> call.startsWith("unwrap")));
        assertTrue(ArrayUtility.isNullOrEmpty(revealed));
    }

    @ParameterizedTest
    @ValueSource(ints = {
        0,   // magic
        4,   // format version
        5,   // wrapping key version
        30,  // ciphertext
        278, // ciphertext, last byte
        279, // signing key version
        300  // signature
    })
    void unwrap_AWrappedDekChangedAnywhere_IsRefused(int offset) {
        var wrapper = wrapper();
        var wrapped = wrap(wrapper, random(32));
        wrapped[offset] ^= 0x01;

        assertFailsWith(CryptographicException.class, wrapper.unwrapAsync(wrapped, new byte[64]));
    }

    @Test
    void unwrap_UnderAnotherContext_IsRefused() {
        var wrapped = wrap(wrapper(), random(32));

        assertFailsWith(CryptographicException.class, wrapper("com.example.other").unwrapAsync(wrapped, new byte[64]));
        assertFailsWith(CryptographicException.class, wrapper(null).unwrapAsync(wrapped, new byte[64]));
    }

    @Test
    void unwrap_ByAWrapperPinnedToOtherKeys_IsRefused() {
        var wrapped = wrap(wrapper(), random(32));
        vault.addVersion("other-sign", FakeKeyVault.p256());

        var other = wrapper(CONTEXT, FakeKeyVault.WRAPPING_KEY_ID, FakeKeyVault.VAULT + "/keys/other-sign");

        assertFailsWith(CryptographicException.class, other.unwrapAsync(wrapped, new byte[64]));
    }

    @ParameterizedTest
    @ValueSource(strings = {FakeKeyVault.WRAPPING_KEY_NAME, FakeKeyVault.SIGNING_KEY_NAME})
    void unwrap_WhenTheRecordedVersionHasBeenPurged_IsRefused(String keyName) {
        var version = vault.currentVersion(keyName);
        var wrapped = wrap(wrapper(), random(32));
        vault.addVersion(keyName, keyName.equals(FakeKeyVault.WRAPPING_KEY_NAME) ? FakeKeyVault.rsa(2048) : FakeKeyVault.p256());
        vault.purge(keyName, version);

        var exception = assertFailsWith(CryptographicException.class, wrapper().unwrapAsync(wrapped, new byte[64]));

        assertInstanceOf(HttpResponseException.class, exception.getCause());
        assertTrue(exception.getMessage().contains("KeyNotFound (HTTP 404)"), exception.getMessage());
    }

    @Test
    void unwrap_RefusesWhatIsNotAWrappedDek_AndZeroesTheResult() {
        var revealed = filled(32, 0xAA);

        assertFailsWith(CryptographicException.class, wrapper().unwrapAsync(random(200), revealed));

        assertTrue(ArrayUtility.isNullOrEmpty(revealed));
        assertTrue(vault.calls.isEmpty());
    }

    @Test
    void unwrap_IntoAResultTooSmall_IsRefused_AndZeroesIt() {
        var wrapper = wrapper();
        var wrapped = wrap(wrapper, random(32));
        var small = filled(16, 0xAA);

        var exception = assertFailsWith(IllegalArgumentException.class, wrapper.unwrapAsync(wrapped, small));

        assertTrue(exception.getMessage().contains("result holds 16"));
        assertTrue(ArrayUtility.isNullOrEmpty(small));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, AzureKeyVaultKeyWrapperImpl.MAX_PLAINTEXT_LENGTH + 1})
    void wrap_RefusesAPlaintextRsaOaepCanNotWrap(int length) {
        var wrapper = wrapper();

        var exception = assertThrows(IllegalArgumentException.class, () -> wrapper.wrapAsync(new byte[length], new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(exception.getMessage().contains("got " + length));
        assertTrue(vault.calls.isEmpty());
    }

    @Test
    void wrap_IntoAResultTooSmall_IsRefused() {
        var exception = assertFailsWith(IllegalArgumentException.class, wrapper().wrapAsync(new byte[32], new byte[100]));

        assertTrue(exception.getMessage().contains("result holds 100"));
    }

    @Test
    void nullArguments_AreRefused() {
        var wrapper = wrapper();

        assertThrows(NullPointerException.class, () -> wrapper.wrapAsync(null, new byte[WrappedKeyLimits.MAX_BYTES]));
        assertThrows(NullPointerException.class, () -> wrapper.wrapAsync(new byte[32], null));
        assertThrows(NullPointerException.class, () -> wrapper.unwrapAsync(null, new byte[32]));
        assertThrows(NullPointerException.class, () -> wrapper.unwrapAsync(new byte[200], null));
        assertThrows(NullPointerException.class, () -> wrapper.generateAndWrapAsync(null));
        assertTrue(vault.calls.isEmpty());
    }

    @Test
    void wrap_UnderAnRsaKeyTooLargeForAKeyFile_IsRefused_BeforeSigning() {
        vault.addVersion(FakeKeyVault.WRAPPING_KEY_NAME, FakeKeyVault.rsa(4096));

        var exception = assertFailsWith(CryptographicException.class, wrapper().wrapAsync(new byte[32], new byte[2 * WrappedKeyLimits.MAX_BYTES]));

        assertTrue(exception.getMessage().contains("2048- or 3072-bit"));
        assertTrue(vault.calls.stream().noneMatch(call -> call.startsWith("sign")));
    }

    @Test
    void wrap_UnderAnRsa3072Key_FitsAKeyFile() {
        vault.addVersion(FakeKeyVault.WRAPPING_KEY_NAME, FakeKeyVault.rsa(3072));
        var wrapper = wrapper();
        var dek = random(32);

        var wrapped = wrap(wrapper, dek);

        assertTrue(wrapped.length <= WrappedKeyLimits.MAX_BYTES);
        assertArrayEquals(dek, unwrap(wrapper, wrapped));
    }

    @Test
    void wrap_WhenTheSigningKeyIsNotP256_IsRefused() {
        vault.signatureOverride = signature -> Arrays.copyOf(signature, signature.length + 8);

        var exception = assertFailsWith(CryptographicException.class, wrapper().wrapAsync(new byte[32], new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(exception.getMessage().contains("EC P-256"));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
        "https://hkdfguard-test.vault.azure.net/keys/someone-else/0123456789abcdef0123456789abcdef | instead",
        "https://other-vault.vault.azure.net/keys/hkdfguard-wrap/0123456789abcdef0123456789abcdef  | instead",
        "https://hkdfguard-test.vault.azure.net/keys/hkdfguard-wrap                                | instead",
        "not a uri                                                                                 | isn't a key identifier",
        "https://example.com/                                                                      | isn't a key identifier"
    })
    void wrap_WhenKeyVaultReportsAnotherKey_IsRefused(String reported, String expected) {
        vault.reportedKeyId = keyId -> reported;

        var exception = assertFailsWith(CryptographicException.class, wrapper().wrapAsync(new byte[32], new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(exception.getMessage().contains(expected), exception.getMessage());
    }

    @Test
    void wrap_WhenKeyVaultReportsAVersionThatIsNotKeyVaults_IsRefused() {
        vault.reportedKeyId = keyId -> FakeKeyVault.WRAPPING_KEY_ID + "/notakeyvaultversion";

        var exception = assertFailsWith(CryptographicException.class, wrapper().wrapAsync(new byte[32], new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(exception.getMessage().contains("not 32 hex digits"), exception.getMessage());
    }

    @Test
    void wrap_WhenKeyVaultReportsNoKey_IsRefused() {
        vault.reportedKeyId = keyId -> null;

        assertFailsWith(CryptographicException.class, wrapper().wrapAsync(new byte[32], new byte[WrappedKeyLimits.MAX_BYTES]));
    }

    @ParameterizedTest
    @ValueSource(strings = {"wrap", "sign", "verify", "unwrap"})
    void keyVaultRefusals_AreCryptographicExceptions_NamingTheErrorAndStatus(String operation) {
        var wrapper = wrapper();
        var wrapped = wrap(wrapper, random(32));
        vault.failures.put(operation, FakeKeyVault.refusal(403, "Forbidden"));

        var exception = assertFailsWith(CryptographicException.class, operation.equals("wrap") || operation.equals("sign")
                ? wrapper.wrapAsync(new byte[32], new byte[WrappedKeyLimits.MAX_BYTES])
                : wrapper.unwrapAsync(wrapped, new byte[64]));

        assertTrue(exception.getMessage().contains(operation + " failed"), exception.getMessage());
        assertTrue(exception.getMessage().contains("Forbidden (HTTP 403)"), exception.getMessage());
        assertInstanceOf(HttpResponseException.class, exception.getCause());
    }

    @Test
    void refusalWithoutAnErrorCode_IsStillNamed() {
        vault.failures.put("wrap", new HttpResponseException("Server error.", StubHttpResponse.error(500, "x"), null));

        var exception = assertFailsWith(CryptographicException.class, wrapper().wrapAsync(new byte[32], new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(exception.getMessage().endsWith("error (HTTP 500)."), exception.getMessage());
    }

    @Test
    void clientSideFailures_AreCryptographicExceptions() {
        vault.failures.put("wrap", new IllegalStateException("no token"));

        var exception = assertFailsWith(CryptographicException.class, wrapper().wrapAsync(new byte[32], new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(exception.getMessage().contains("no token"));
        assertInstanceOf(IllegalStateException.class, exception.getCause());
    }

    @Test
    void aClientThatThrowsInsteadOfReturningAFuture_FailsTheFuture() {
        Function<String, KeyVaultKeyClient> throwing = keyId -> {
            throw new IllegalStateException("Thrown, not returned.");
        };
        var wrapper = new AzureKeyVaultKeyWrapperImpl(FakeKeyVault.WRAPPING_KEY_ID, FakeKeyVault.SIGNING_KEY_ID, throwing, CONTEXT, null);

        var exception = assertFailsWith(CryptographicException.class, wrapper.generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(exception.getMessage().endsWith("Thrown, not returned."));
    }

    @Test
    void cancellation_IsLeftAsItIs() {
        vault.failures.put("wrap", new CancellationException("Cancelled by the caller."));

        assertFailsWith(CancellationException.class, wrapper().wrapAsync(new byte[32], new byte[WrappedKeyLimits.MAX_BYTES]));
    }

    @Test
    void cancellingTheFuture_CancelsTheKeyVaultRequest() {
        vault.deferred = true;

        var future = wrapper().generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]);
        assertTrue(future.cancel(true));

        var call = vault.futures.getFirst();
        assertTrue(call.isCancelled());
        assertThrows(CancellationException.class, () -> call.get(1, TimeUnit.SECONDS));
    }

    @Test
    void cancellingAnUnwrap_ZeroesTheResult_AndUnwrapsNothing() {
        var wrapper = wrapper();
        var wrapped = wrap(wrapper, random(32));
        vault.calls.clear();
        vault.deferred = true;
        var result = filled(32, 0xAA);

        CompletableFuture<Integer> future = wrapper.unwrapAsync(wrapped, result);
        assertTrue(future.cancel(true));
        Futures.sleep(200);

        assertTrue(ArrayUtility.isNullOrEmpty(result));
        assertTrue(vault.futures.getLast().isCancelled());
        assertTrue(vault.calls.stream().noneMatch(call -> call.startsWith("unwrap")), vault.calls.toString());
    }

    @Test
    void aVerifyAnsweredAfterTheCallerCancelled_SendsNoUnwrap() {
        // A verify the cancellation can't stop - already answered, say - completes afterwards.
        var wrapped = wrap(wrapper(), random(32));
        var verify = new CompletableFuture<VerifyResult>() {
            @Override
            public boolean cancel(boolean mayInterruptIfRunning) {
                return false;
            }
        };
        Function<String, KeyVaultKeyClient> clients = keyId -> new DelegatingClient(vault.client(keyId)) {
            @Override
            public CompletableFuture<VerifyResult> verifyData(SignatureAlgorithm algorithm, byte[] data, byte[] signature) {
                return verify;
            }
        };
        var wrapper = new AzureKeyVaultKeyWrapperImpl(FakeKeyVault.WRAPPING_KEY_ID, FakeKeyVault.SIGNING_KEY_ID, clients, CONTEXT, null);
        vault.calls.clear();
        var result = filled(32, 0xAA);

        var future = wrapper.unwrapAsync(wrapped, result);
        assertTrue(future.cancel(true));
        verify.complete(new VerifyResult(true, SignatureAlgorithm.ES256, FakeKeyVault.SIGNING_KEY_ID));

        assertTrue(vault.calls.isEmpty(), vault.calls.toString());
        assertTrue(ArrayUtility.isNullOrEmpty(result));
    }

    /** Passes every call to another client; tests override the ones they replace. */
    private static class DelegatingClient implements KeyVaultKeyClient {
        private final KeyVaultKeyClient inner;

        DelegatingClient(KeyVaultKeyClient inner) {
            this.inner = inner;
        }

        @Override
        public CompletableFuture<WrapResult> wrapKey(KeyWrapAlgorithm algorithm, byte[] key) {
            return inner.wrapKey(algorithm, key);
        }

        @Override
        public CompletableFuture<UnwrapResult> unwrapKey(KeyWrapAlgorithm algorithm, byte[] encryptedKey) {
            return inner.unwrapKey(algorithm, encryptedKey);
        }

        @Override
        public CompletableFuture<SignResult> signData(SignatureAlgorithm algorithm, byte[] data) {
            return inner.signData(algorithm, data);
        }

        @Override
        public CompletableFuture<VerifyResult> verifyData(SignatureAlgorithm algorithm, byte[] data, byte[] signature) {
            return inner.verifyData(algorithm, data, signature);
        }
    }

    @Test
    void publicConstructor_MakesNoCallUntilTheWrapperIsUsed() {
        TokenCredential failing = request -> Mono.error(new IllegalStateException("No token in tests."));

        new AzureKeyVaultKeyWrapperImpl(FakeKeyVault.WRAPPING_KEY_ID, FakeKeyVault.SIGNING_KEY_ID, failing);
    }

    @Test
    void aCryptoProvider_GeneratesAndRevealsItsDekThroughKeyVault() {
        try (var provider = await(new AesGcmCryptoProviderFactoryImpl().createEphemeralAsync(wrapper(), 60))) {
            var expected = "hello, key vault".getBytes(StandardCharsets.UTF_8);
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
        assumeNotMacOsPrivateTemp();

        var dir = Files.createTempDirectory("hkdfguard-keys-");
        var path = Files.write(dir.resolve("v1.key"), wrap(wrapper(), random(32)));
        try {
            assertFailsWith(AccessDeniedException.class, wrapper().readKeyFileAsync(path));
        } finally {
            Files.delete(path);
            Files.delete(dir);
        }
    }

    @Test
    void readKeyFile_WithANullTrust_TrustsAdministratorsOnly() throws IOException {
        // The same refusal as the default: null is AdministratorsOnly, never "anyone".
        assumeNotMacOsPrivateTemp();

        var wrapper = new AzureKeyVaultKeyWrapperImpl(FakeKeyVault.WRAPPING_KEY_ID, FakeKeyVault.SIGNING_KEY_ID, vault::client, null, null);
        var dir = Files.createTempDirectory("hkdfguard-keys-");
        var path = Files.write(dir.resolve("v1.key"), random(300));
        try {
            var exception = assertFailsWith(AccessDeniedException.class, wrapper.readKeyFileAsync(path));
            assertSame(AccessDeniedException.class, exception.getClass());
        } finally {
            Files.delete(path);
            Files.delete(dir);
        }
    }

    @Test
    @EnabledOnOs(value = OS.WINDOWS, disabledReason = "Windows only.")
    void readKeyFile_WithTheWritersAccountTrusted_ReadsTheFile() throws IOException {
        var trust = KeyFileTrust.ADMINISTRATORS_ONLY.withWindowsPrincipals(WindowsTempDirectory.currentUserSid());
        var wrapper = new AzureKeyVaultKeyWrapperImpl(FakeKeyVault.WRAPPING_KEY_ID, FakeKeyVault.SIGNING_KEY_ID, vault::client, CONTEXT, trust);
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
        var trust = KeyFileTrust.ADMINISTRATORS_ONLY.withWindowsPrincipals("S-1-1-0");
        var wrapper = new AzureKeyVaultKeyWrapperImpl(FakeKeyVault.WRAPPING_KEY_ID, FakeKeyVault.SIGNING_KEY_ID, vault::client, CONTEXT, trust);
        try (var dir = new WindowsTempDirectory()) {
            var path = dir.write("v1.key", random(300));

            assertFailsWith(IllegalArgumentException.class, wrapper.readKeyFileAsync(path));
        }
    }

    @Test
    void readKeyFile_NullPath_IsRefused() {
        var wrapper = wrapper();

        assertThrows(NullPointerException.class, () -> wrapper.readKeyFileAsync((Path) null));
    }

    private static void assumeNotMacOsPrivateTemp() {
        var temp = System.getProperty("java.io.tmpdir");
        Assumptions.assumeFalse(System.getProperty("os.name", "").toLowerCase(Locale.ROOT).startsWith("mac") && temp.startsWith("/var/folders/"),
                "macOS's per-user temp folder is private to its user; TrustedKeyFileTest covers macOS.");
    }
}
