package io.github.runsecure.hkdfguard.keywrapping.azurekeyvault;

import static io.github.runsecure.hkdfguard.keywrapping.azurekeyvault.Futures.assertFailsWith;
import static io.github.runsecure.hkdfguard.keywrapping.azurekeyvault.Futures.await;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.azure.core.credential.TokenCredential;
import com.azure.core.exception.HttpResponseException;
import io.github.runsecure.hkdfguard.abstractions.ArrayUtility;
import io.github.runsecure.hkdfguard.abstractions.CryptographicException;
import io.github.runsecure.hkdfguard.abstractions.WrappedKeyLimits;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

/**
 * The wrapper over the real Key Vault clients - the public constructor's - with Key Vault's REST
 * API stubbed under them ({@link KeyVaultHttpStub}): what reaches the wire, and what the SDK's
 * answers and failures become.
 */
class KeyVaultClientsTest {
    private static final String CONTEXT = "com.example.myapp";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final FakeKeyVault vault = new FakeKeyVault();
    private final KeyVaultHttpStub stub = new KeyVaultHttpStub(vault);

    private AzureKeyVaultKeyWrapperImpl wrapper() {
        return wrapper(KeyVaultHttpStub.CREDENTIAL);
    }

    private AzureKeyVaultKeyWrapperImpl wrapper(TokenCredential credential) {
        return new AzureKeyVaultKeyWrapperImpl(FakeKeyVault.WRAPPING_KEY_ID, FakeKeyVault.SIGNING_KEY_ID, credential, CONTEXT, null, stub.clientOptions());
    }

    private static byte[] wrap(AzureKeyVaultKeyWrapperImpl wrapper, byte[] dek) {
        var wrapped = new byte[WrappedKeyLimits.MAX_BYTES];
        int length = await(wrapper.wrapAsync(dek, wrapped));
        return Arrays.copyOf(wrapped, length);
    }

    private static byte[] random(int length) {
        var bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    @Test
    void wrapThenUnwrap_RoundTripsTheDek_AndUnwrapCallsOnlyTheRecordedVersions() {
        var wrapper = wrapper();
        var dek = random(32);
        var wrapped = wrap(wrapper, dek);
        var wrapVersion = vault.currentVersion(FakeKeyVault.WRAPPING_KEY_NAME);
        var signVersion = vault.currentVersion(FakeKeyVault.SIGNING_KEY_NAME);
        stub.requests.clear();

        var revealed = new byte[32];
        assertEquals(32, await(wrapper.unwrapAsync(wrapped, revealed)));

        assertArrayEquals(dek, revealed);
        // The signing key's recorded version is fetched and the signature checked with it here;
        // only then is the wrapping key's recorded version asked to unwrap.
        assertEquals(List.of(
                "GET /keys/" + FakeKeyVault.SIGNING_KEY_NAME + "/" + signVersion,
                "GET /keys/" + FakeKeyVault.WRAPPING_KEY_NAME + "/" + wrapVersion,
                "POST /keys/" + FakeKeyVault.WRAPPING_KEY_NAME + "/" + wrapVersion + "/unwrapkey"), stub.requests);
    }

    @Test
    void aWrappedDek_IsByteForByteWhatTheSeamProduces() {
        // The same vault through the seam the other tests use: the same envelope, bar the
        // randomized ciphertext and signature, so those tests describe the real clients too.
        var throughClients = WrappedDekEnvelope.parse(wrap(wrapper(), random(32)));
        var throughSeam = WrappedDekEnvelope.parse(wrap(
                new AzureKeyVaultKeyWrapperImpl(FakeKeyVault.WRAPPING_KEY_ID, FakeKeyVault.SIGNING_KEY_ID, vault::client, CONTEXT, null), random(32)));

        assertEquals(throughSeam.wrappingKeyVersion(), throughClients.wrappingKeyVersion());
        assertEquals(throughSeam.signingKeyVersion(), throughClients.signingKeyVersion());
        assertEquals(throughSeam.wrappedDek().length, throughClients.wrappedDek().length);
    }

    @Test
    void withoutPermissionToReadTheKeys_EverythingIsDoneInTheVault() {
        // A principal that may use the keys but not read them (no keys/get): the clients can't
        // fetch the public keys, so they verify in the vault instead.
        stub.refusals.put("get", Map.entry(403, "Forbidden"));
        var wrapper = wrapper();
        var dek = random(32);
        var wrapped = wrap(wrapper, dek);
        stub.requests.clear();

        var revealed = new byte[32];
        await(wrapper.unwrapAsync(wrapped, revealed));

        assertArrayEquals(dek, revealed);
        assertTrue(stub.requests.stream().anyMatch(request -> request.endsWith("/verify")), stub.requests.toString());
    }

    @Test
    void aForgedSignature_IsRefused_WithoutUnwrapping() {
        var wrapper = wrapper();
        var wrapped = wrap(wrapper, random(32));
        wrapped[wrapped.length - 1] ^= 0x01;
        stub.requests.clear();
        var revealed = new byte[32];
        Arrays.fill(revealed, (byte) 0xAA);

        var exception = assertFailsWith(CryptographicException.class, wrapper.unwrapAsync(wrapped, revealed));

        assertTrue(exception.getMessage().contains("signature doesn't verify"), exception.getMessage());
        assertTrue(stub.requests.stream().noneMatch(request -> request.endsWith("/unwrapkey")), stub.requests.toString());
        assertTrue(ArrayUtility.isNullOrEmpty(revealed));
    }

    @Test
    void aRefusal_NamesKeyVaultsErrorCodeAndTheStatus() {
        var wrapper = wrapper();
        var wrapped = wrap(wrapper, random(32));
        stub.refusals.put("unwrapkey", Map.entry(403, "Forbidden"));

        var exception = assertFailsWith(CryptographicException.class, wrapper.unwrapAsync(wrapped, new byte[32]));

        assertEquals("Azure Key Vault unwrap failed for key '" + FakeKeyVault.WRAPPING_KEY_NAME + "': Forbidden (HTTP 403).", exception.getMessage());
        assertInstanceOf(HttpResponseException.class, exception.getCause());
    }

    @Test
    void aPurgedSigningKeyVersion_IsRefused() {
        var version = vault.currentVersion(FakeKeyVault.SIGNING_KEY_NAME);
        var wrapper = wrapper();
        var wrapped = wrap(wrapper, random(32));
        vault.addVersion(FakeKeyVault.SIGNING_KEY_NAME, FakeKeyVault.p256());
        vault.purge(FakeKeyVault.SIGNING_KEY_NAME, version);

        var exception = assertFailsWith(CryptographicException.class, wrapper().unwrapAsync(wrapped, new byte[32]));

        assertTrue(exception.getMessage().contains("verify failed for key '" + FakeKeyVault.SIGNING_KEY_NAME + "': KeyNotFound (HTTP 404)"),
                exception.getMessage());
    }

    @Test
    void aCredentialThatCanNotGetAToken_IsACryptographicException() {
        TokenCredential failing = request -> Mono.error(new IllegalStateException("No token in tests."));

        var exception = assertFailsWith(CryptographicException.class, wrapper(failing).generateAndWrapAsync(new byte[WrappedKeyLimits.MAX_BYTES]));

        assertTrue(exception.getMessage().startsWith("Azure Key Vault wrap failed for key '" + FakeKeyVault.WRAPPING_KEY_NAME + "': "),
                exception.getMessage());
        assertTrue(exception.getMessage().contains("No token in tests."), exception.getMessage());
    }
}
