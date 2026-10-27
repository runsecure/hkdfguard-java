package io.github.runsecure.hkdfguard.keywrapping.azurekeyvault;

import com.azure.core.http.HttpHeaderName;
import com.azure.core.http.HttpHeaders;
import com.azure.core.http.HttpMethod;
import com.azure.core.http.HttpRequest;
import com.azure.core.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

/** A canned HTTP response, for {@link KeyVaultHttpStub} and for refusals shaped like the SDK's. */
final class StubHttpResponse extends HttpResponse {
    private final int status;
    private final HttpHeaders headers;
    private final byte[] body;

    StubHttpResponse(HttpRequest request, int status, HttpHeaders headers, String body) {
        super(request);
        this.status = status;
        this.headers = headers;
        this.body = body.getBytes(StandardCharsets.UTF_8);
    }

    static StubHttpResponse json(HttpRequest request, int status, String json) {
        return new StubHttpResponse(request, status, new HttpHeaders().set(HttpHeaderName.CONTENT_TYPE, "application/json; charset=utf-8"), json);
    }

    /** Key Vault's error response: {@code {"error":{"code":...,"message":...}}}. */
    static StubHttpResponse error(HttpRequest request, int status, String code) {
        return json(request, status, "{\"error\":{\"code\":\"" + code + "\",\"message\":\"" + code + " from the stub vault.\"}}");
    }

    static StubHttpResponse error(int status, String code) {
        return error(new HttpRequest(HttpMethod.POST, FakeKeyVault.VAULT), status, code);
    }

    /** The body as the SDK deserializes an error body into an HttpResponseException's value. */
    Object errorValue() {
        var code = new String(body, StandardCharsets.UTF_8).replaceAll(".*\"code\":\"([^\"]*)\".*", "$1");
        return Map.of("error", Map.of("code", code, "message", code + " from the stub vault."));
    }

    String bodyText() {
        return new String(body, StandardCharsets.UTF_8);
    }

    @Override
    public int getStatusCode() {
        return status;
    }

    @Override
    @Deprecated
    public String getHeaderValue(String name) {
        return headers.getValue(HttpHeaderName.fromString(name));
    }

    @Override
    public HttpHeaders getHeaders() {
        return headers;
    }

    @Override
    public Flux<ByteBuffer> getBody() {
        return Flux.just(ByteBuffer.wrap(body.clone()));
    }

    @Override
    public Mono<byte[]> getBodyAsByteArray() {
        return Mono.just(body.clone());
    }

    @Override
    public Mono<String> getBodyAsString() {
        return Mono.just(bodyText());
    }

    @Override
    public Mono<String> getBodyAsString(Charset charset) {
        return Mono.just(new String(body, charset));
    }
}
