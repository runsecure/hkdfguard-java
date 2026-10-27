package io.github.runsecure.hkdfguard.keywrapping.azurekeyvault;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.exception.HttpResponseException;
import com.azure.core.http.HttpClient;
import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpMethod;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.HttpResponse;
import com.azure.core.http.policy.FixedDelayOptions;
import com.azure.core.http.policy.RetryOptions;
import com.azure.json.JsonProviders;
import com.azure.json.JsonReader;
import com.azure.security.keyvault.keys.cryptography.CryptographyClientBuilder;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import reactor.core.publisher.Mono;

/**
 * Key Vault's REST API over a {@link FakeKeyVault}, as an azure-core {@link HttpClient}: the real
 * Key Vault clients, given it, make every request they would make of a vault - the authentication
 * challenge, fetching a key to verify with locally, wrapkey, unwrapkey, sign, verify - and get the answers a
 * vault would give, with no network. Every authorized request is recorded as "METHOD path".
 */
final class KeyVaultHttpStub implements HttpClient {
    static final String TOKEN = "stub-token";

    /** A credential that always has a token, which this stub accepts. */
    static final TokenCredential CREDENTIAL = request -> Mono.just(new AccessToken(TOKEN, OffsetDateTime.now().plusHours(1)));

    private static final Pattern PATH = Pattern.compile("/keys/([^/]+)/([^/]*)(?:/(wrapkey|unwrapkey|sign|verify))?");
    private static final Base64.Encoder BASE64URL = Base64.getUrlEncoder().withoutPadding();

    private final FakeKeyVault vault;

    /** Every authorized request, as "METHOD path". */
    final List<String> requests = new CopyOnWriteArrayList<>();

    /** Refuses the named operation ("get", "wrapkey", "unwrapkey", "sign", "verify") with this status and error code. */
    final Map<String, Map.Entry<Integer, String>> refusals = new ConcurrentHashMap<>();

    KeyVaultHttpStub(FakeKeyVault vault) {
        this.vault = vault;
    }

    /** Sets a client builder up to call this stub, without retries. */
    Consumer<CryptographyClientBuilder> clientOptions() {
        return builder -> builder.httpClient(this).retryOptions(new RetryOptions(new FixedDelayOptions(0, Duration.ZERO)));
    }

    @Override
    public Mono<HttpResponse> send(HttpRequest request) {
        return Mono.fromSupplier(() -> answer(request));
    }

    private HttpResponse answer(HttpRequest request) {
        // Key Vault's challenge: the first request goes without a token, and learns where to get one.
        if (request.getHeaders().getValue(HttpHeaderName.AUTHORIZATION) == null) {
            return new StubHttpResponse(request, 401, new HttpHeaders().set(HttpHeaderName.WWW_AUTHENTICATE,
                    "Bearer authorization=\"https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000\", resource=\"https://vault.azure.net\""), "");
        }
        if (!("Bearer " + TOKEN).equals(request.getHeaders().getValue(HttpHeaderName.AUTHORIZATION)))
            return StubHttpResponse.error(request, 401, "Unauthorized");

        var url = request.getUrl();
        var path = PATH.matcher(url.getPath());
        if (!("https://" + url.getHost()).equals(FakeKeyVault.VAULT) || !path.matches())
            return StubHttpResponse.error(request, 404, "NotFound");
        requests.add(request.getHttpMethod() + " " + url.getPath());

        var operation = path.group(3) == null ? "get" : path.group(3);
        var refusal = refusals.get(operation);
        if (refusal != null)
            return StubHttpResponse.error(request, refusal.getKey(), refusal.getValue());

        var keyId = FakeKeyVault.VAULT + "/keys/" + path.group(1) + (path.group(2).isEmpty() ? "" : "/" + path.group(2));
        try {
            var resolved = vault.resolve(keyId);
            if (request.getHttpMethod() == HttpMethod.GET)
                return StubHttpResponse.json(request, 200, "{\"key\":" + jsonWebKey(resolved) + ",\"attributes\":{\"enabled\":true}}");

            var body = body(request);
            return switch (operation) {
                case "wrapkey" -> result(request, resolved, FakeKeyVault.rsaOaep(Cipher.ENCRYPT_MODE, resolved, decode(body, "value", "RSA-OAEP-256")));
                case "unwrapkey" -> result(request, resolved, FakeKeyVault.rsaOaep(Cipher.DECRYPT_MODE, resolved, decode(body, "value", "RSA-OAEP-256")));
                // The client hashes the data and sends the digest.
                case "sign" -> result(request, resolved, vault.sign("NONEwithECDSAinP1363Format", resolved, decode(body, "value", "ES256")));
                // Only when the client couldn't fetch the key to verify with locally.
                default -> StubHttpResponse.json(request, 200, "{\"value\":"
                        + FakeKeyVault.verify("NONEwithECDSAinP1363Format", resolved, decode(body, "digest", "ES256"), decode(body, "value", "ES256")) + "}");
            };
        } catch (HttpResponseException e) {
            return StubHttpResponse.error(request, e.getResponse().getStatusCode(), KeyVaultErrors.code(e));
        }
    }

    private static HttpResponse result(HttpRequest request, FakeKeyVault.Resolved resolved, byte[] value) {
        return StubHttpResponse.json(request, 200, "{\"kid\":\"" + resolved.keyId() + "\",\"value\":\"" + BASE64URL.encodeToString(value) + "\"}");
    }

    private static String jsonWebKey(FakeKeyVault.Resolved resolved) {
        var kid = resolved.keyId();
        if (resolved.keyPair().getPublic() instanceof RSAPublicKey rsa)
            return "{\"kid\":\"" + kid + "\",\"kty\":\"RSA\",\"key_ops\":[\"encrypt\",\"decrypt\",\"wrapKey\",\"unwrapKey\"],\"n\":\""
                    + unsigned(rsa.getModulus(), (rsa.getModulus().bitLength() + 7) / 8) + "\",\"e\":\"" + unsigned(rsa.getPublicExponent(), 3) + "\"}";
        var ec = (ECPublicKey) resolved.keyPair().getPublic();
        return "{\"kid\":\"" + kid + "\",\"kty\":\"EC\",\"crv\":\"P-256\",\"key_ops\":[\"sign\",\"verify\"],\"x\":\""
                + unsigned(ec.getW().getAffineX(), 32) + "\",\"y\":\"" + unsigned(ec.getW().getAffineY(), 32) + "\"}";
    }

    // Big-endian, unsigned, exactly length bytes, base64url.
    private static String unsigned(BigInteger value, int length) {
        var bytes = value.toByteArray();
        var fixed = new byte[length];
        var copy = Math.min(bytes.length, length);
        System.arraycopy(bytes, bytes.length - copy, fixed, length - copy, copy);
        return BASE64URL.encodeToString(fixed);
    }

    private static Map<String, Object> body(HttpRequest request) {
        try (var reader = JsonProviders.createReader(request.getBodyAsBinaryData().toBytes())) {
            return reader.readMap(JsonReader::readUntyped);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static byte[] decode(Map<String, Object> body, String field, String algorithm) {
        if (!algorithm.equals(body.get("alg")))
            throw new AssertionError("Expected " + algorithm + ", but the client sent " + body.get("alg") + ".");
        return Base64.getUrlDecoder().decode((String) body.get(field));
    }

    @Override
    public String toString() {
        return "KeyVaultHttpStub" + Arrays.toString(requests.toArray());
    }
}
